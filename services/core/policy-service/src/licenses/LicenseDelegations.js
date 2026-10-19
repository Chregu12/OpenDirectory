'use strict';

const { provenMfa } = require('../../../../../packages/mfa-authorization-contract');
const { validContext } = require('../../../../../packages/identity-authorization-contract');
const { createAccessStateClient } = require('../../../../../packages/oidc-access-state');
const { getLicensePermissions } = require('../middleware/licenseAccess');
const { requirePrincipal, UUID } = require('./LicensePrincipal');
const { LicenseError } = require('./LicenseError');
const { scopeContext } = require('./LicenseScopeContext');
const fail = (status, code) => { throw new LicenseError(status, code); };
const uuid = value => { if (typeof value !== 'string' || !UUID.test(value)) fail(400, 'canonical_uuid_required'); return value; };
const DUTIES = Object.freeze({ reader: ['pool.read','grants.read','requests.read'], allocator: ['pool.read','grants.read','requests.read','assignments.manage'], approver: ['pool.read','grants.read','requests.read','requests.review'] });
const tag = row => `"od-license-delegation:${row.id}:${row.version}"`;
function fields(body, keys) {
  if (!body || Array.isArray(body) || Object.keys(body).length !== keys.length || keys.some(key => !Object.hasOwn(body, key))) fail(400, 'invalid_delegation_fields');
  if (body.confirm !== true || typeof body.reason !== 'string' || body.reason.trim().length < 10 || body.reason.length > 500 || /[\u0000-\u001f\u007f]/.test(body.reason)) fail(400, 'confirmed_reason_required');
}
function view(row) {
  if (!row) fail(404, 'delegation_not_found');
  return { id: row.id, licenseId: row.license_id, userId: row.user_id, duty: row.duty, version: String(row.version), createdAt: row.created_at.toISOString(),
    expiresAt: row.expires_at.toISOString(), revokedAt: row.revoked_at?.toISOString() || null, state: row.revoked_at ? 'revoked' : row.expires_at <= row.observed_at ? 'expired' : 'active' };
}
const SELECT = 'SELECT grants.*,license_now() AS observed_at FROM license_scope_grants grants JOIN license_catalog legacy_catalog ON legacy_catalog.id=grants.license_id AND legacy_catalog.business_tenant_id IS NULL';

class LicenseDelegations {
  constructor(allocator, { source = allocator.users.source, revalidate } = {}) {
    this.allocator = allocator; this.database = allocator.database; this.source = source; this.revalidate = revalidate || createAccessStateClient();
  }
  actor(user, principal, permission, write = false) {
    if (scopeContext.getStore() && ['read','manage'].includes(permission)) fail(403, 'scope_control_plane_not_delegated');
    requirePrincipal(principal);
    if (user?.actor_type !== 'user' || user.iss !== principal.issuer || user.sub !== principal.subject || !validContext(user.identity_authorization)
      || user.identity_authorization.userId !== principal.userId) fail(403, 'canonical_human_required');
    if (permission && !getLicensePermissions(user).includes('licenses.delegations.' + permission)) fail(403, 'forbidden');
    if (write && (!provenMfa(user) || user.auth_time > Math.floor(Date.now() / 1000) + 5 || Math.floor(Date.now() / 1000) - user.auth_time > 300)) fail(428, 'fresh_mfa_required');
    return principal.userId;
  }
  async context(client, body, user, principal) {
    await client.query("SELECT set_config('opendirectory.scope_proof',$1,true),set_config('opendirectory.scope_reason',$2,true)",
      [JSON.stringify({ userId: principal.userId, issuer: principal.issuer, subject: principal.subject, authTime: user.auth_time, factorRevision: user.mfa_authorization.revision }), body.reason.trim()]);
  }
  async subject(userId, authorization) {
    await this.allocator.assertLegacySubject(userId);
    const snapshot = await this.source.delegate(userId, authorization);
    if (!snapshot.enabled || !snapshot.linked || !snapshot.delegationRevision) fail(409, 'active_canonical_delegate_required');
    return snapshot;
  }
  async create(body, user, principal, authorization) {
    const actor = this.actor(user, principal, 'manage', true);
    fields(body, ['licenseId','userId','duty','durationSeconds','reason','confirm']); uuid(body.licenseId); uuid(body.userId);
    if (actor === body.userId || !Object.hasOwn(DUTIES, body.duty) || !Number.isInteger(body.durationSeconds) || body.durationSeconds < 60 || body.durationSeconds > 28800) fail(400, 'independent_bounded_delegation_required');
    await this.allocator.assertPoolAccess(body.licenseId, this.database, { legacyOnly: true });
    const target = await this.subject(body.userId, authorization);
    return this.allocator.transaction(async client => {
      await this.allocator.assertPoolAccess(body.licenseId, client, { legacyOnly: true });
      await this.allocator.lockSubjects(client, actor, [body.userId]); await this.allocator.lockLicense(client, body.licenseId);
      await this.revalidate(authorization, user); this.actor(user, principal, 'manage', true); await this.context(client, body, user, principal);
      const row = (await client.query(`INSERT INTO license_scope_grants(license_id,user_id,issuer,duty,eligibility_revision,delegation_revision,expires_at)
        VALUES($1,$2,$3,$4,$5,$6,date_trunc('milliseconds',license_now())+$7*interval '1 second') RETURNING *,license_now() AS observed_at`,
      [body.licenseId,body.userId,principal.issuer,body.duty,target.revision,target.delegationRevision,body.durationSeconds])).rows[0];
      const current = await this.subject(body.userId, authorization);
      if (current.revision !== target.revision || current.delegationRevision !== target.delegationRevision) fail(409, 'delegate_authority_changed');
      await this.revalidate(authorization, user); this.actor(user, principal, 'manage', true); return view(row);
    });
  }
  async list(licenseId, after, user, principal) {
    this.actor(user, principal, 'read'); uuid(licenseId); if (after !== undefined) uuid(after);
    await this.allocator.assertPoolAccess(licenseId, this.database, { legacyOnly: true });
    const rows = (await this.database.query(`${SELECT} WHERE grants.license_id=$1 AND ($2::uuid IS NULL OR grants.id>$2) ORDER BY grants.id LIMIT 101`, [licenseId,after || null])).rows;
    return { licenseId, delegations: rows.slice(0,100).map(view), hasMore: rows.length>100, nextAfter: rows.length>100 ? rows[99].id : null };
  }
  async revoke(id, expected, body, user, principal, authorization) {
    const actor = this.actor(user, principal, 'manage', true); uuid(id); fields(body, ['reason','confirm']); if (!expected) fail(428, 'version_required');
    const peek = (await this.database.query('SELECT grants.license_id,grants.user_id FROM license_scope_grants grants JOIN license_catalog catalog ON catalog.id=grants.license_id AND catalog.business_tenant_id IS NULL WHERE grants.id=$1', [id])).rows[0]; if (!peek) fail(404, 'delegation_not_found');
    return this.allocator.transaction(async client => {
      await this.allocator.assertPoolAccess(peek.license_id, client, { legacyOnly: true });
      await this.allocator.lockSubjects(client, actor);
      await this.allocator.lockLicense(client, peek.license_id);
      const row = (await client.query(SELECT + ' WHERE grants.id=$1 FOR UPDATE OF grants', [id])).rows[0];
      if (expected !== tag(row)) fail(412, 'delegation_changed'); if (row.revoked_at) fail(409, 'delegation_revoked');
      await this.revalidate(authorization, user); await this.context(client, body, user, principal);
      const changed = (await client.query('UPDATE license_scope_grants SET revoked_at=license_now(),version=version+1 WHERE id=$1 RETURNING *,license_now() AS observed_at', [id])).rows[0];
      await this.revalidate(authorization, user); this.actor(user, principal, 'manage', true); return view(changed);
    });
  }
  async self(user, principal, authorization) {
    const actor = this.actor(user, principal); await this.allocator.assertLegacySubject(actor); const snapshot = await this.source.delegate(actor, authorization);
    if (!snapshot.enabled || !snapshot.linked || !snapshot.delegationRevision) return { userId: actor, delegations: [], truncated: false };
    const rows = (await this.database.query(`${SELECT} LEFT JOIN license_subjects subject ON subject.user_id=grants.user_id::text
      WHERE grants.user_id=$1 AND issuer=$2 AND grants.eligibility_revision=$3 AND delegation_revision=$4 AND revoked_at IS NULL AND expires_at>license_now()
      AND license_scope_grant_usable(grants.id) AND NOT COALESCE(subject.disabled,false) AND subject.directory_enabled IS DISTINCT FROM false ORDER BY grants.expires_at,grants.id LIMIT 101`, [actor,principal.issuer,snapshot.revision,snapshot.delegationRevision])).rows;
    return { userId: actor, delegations: rows.slice(0,100).map(view), truncated: rows.length>100 };
  }
  async run(licenseId, permission, reason, user, principal, authorization, operation) {
    const write = ['assignments.manage','requests.review'].includes(permission);
    if (write) fields({ reason,confirm:true }, ['reason','confirm']); else if (reason !== null) fail(400, 'unexpected_scoped_reason');
    const actor = this.actor(user, principal, 'self', write); uuid(licenseId);
    await this.allocator.assertPoolAccess(licenseId, this.database, { legacyOnly: true });
    const snapshot = await this.subject(actor, authorization);
    const available = (await this.database.query(`${SELECT} WHERE license_id=$1 AND user_id=$2 AND issuer=$3 AND eligibility_revision=$4 AND delegation_revision=$5
      AND revoked_at IS NULL AND expires_at>license_now() AND license_scope_grant_usable(grants.id) ORDER BY grants.id`, [licenseId,actor,principal.issuer,snapshot.revision,snapshot.delegationRevision])).rows;
    const selected = available.find(row => DUTIES[row.duty].includes(permission)); if (!selected) fail(404, 'license_scope_not_found');
    const scope = { database: this.database, licenseId, permission, userId: actor, user,
      verify: async (client, after) => {
        await this.allocator.assertPoolAccess(licenseId, client, { legacyOnly: true });
        this.actor(user, principal, 'self', write);
        const current = await this.subject(actor, authorization);
        const row = (await client.query(`${SELECT} JOIN license_catalog catalog ON catalog.id=grants.license_id
          LEFT JOIN license_subjects subject ON subject.user_id=grants.user_id::text WHERE grants.id=$1 AND grants.version=$2 AND grants.user_id=$3 AND issuer=$4
          AND grants.eligibility_revision=$5 AND delegation_revision=$6 AND revoked_at IS NULL AND expires_at>license_now()
          AND license_scope_grant_usable(grants.id) AND catalog.license_type IN ('per_user','subscription') AND NOT COALESCE(subject.disabled,false) AND subject.directory_enabled IS DISTINCT FROM false ${after ? 'FOR SHARE OF grants' : ''}`,
        [selected.id,selected.version,actor,principal.issuer,current.revision,current.delegationRevision])).rows[0];
        if (!row || !DUTIES[row.duty].includes(permission)) fail(403, 'license_scope_changed');
        await client.query("SELECT set_config('opendirectory.scope_pool',$1,true),set_config('opendirectory.scope_user',$2,true),set_config('opendirectory.scope_grant',$3,true),set_config('opendirectory.scope_permission',$4,true)", [licenseId,actor,row.id,permission]);
        if (after && write) await client.query("INSERT INTO license_scope_audit(grant_id,action,actor,reason,details) VALUES($1,'use',$2,$3,$4)",
          [row.id, JSON.stringify({ userId: actor, issuer: principal.issuer, subject: principal.subject, authTime: user.auth_time, factorRevision: user.mfa_authorization.revision }),reason,
            JSON.stringify({ licenseId, permission, version: String(row.version) })]);
        await this.revalidate(authorization, user); this.actor(user, principal, 'self', write);
        if (!(await client.query('SELECT 1 FROM license_scope_grants WHERE id=$1 AND version=$2 AND license_scope_grant_usable(id)', [selected.id,selected.version])).rows.length) fail(403, 'license_scope_changed');
      } };
    return scopeContext.run(scope, operation);
  }
  async read(licenseId, operation, actor) {
    await this.allocator.assertPoolAccess(licenseId, this.database, { legacyOnly: true });
    return this.allocator.transaction(async client => { await this.allocator.assertPoolAccess(licenseId, client, { legacyOnly: true }); await this.allocator.lockSubjects(client, actor); await this.allocator.lockLicense(client, licenseId); return operation(client); });
  }
}
module.exports = { LicenseDelegations, DUTIES, fields, uuid, tag };
