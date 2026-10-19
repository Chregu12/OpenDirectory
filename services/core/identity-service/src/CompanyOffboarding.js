'use strict';

const { randomUUID } = require('crypto');
const { validUuid, validRevision } = require('../../../../packages/identity-authorization-contract');
const { sameTenantContext } = require('../../../../packages/tenant-authorization-contract');
const { createTenantStateClient } = require('../../../../packages/oidc-tenant-state');
const { CompanyLicenseAuthority } = require('./CompanyLicenseAuthority');
const { requireDirectoryPermissions } = require('./DirectoryAuthority');
const { UserMutator } = require('./UserMutator');
const { userEtag } = require('./DirectoryUsers');
const PERMISSIONS = ['users.update', 'users.status.manage'];
function fail(status, message) { throw Object.assign(new Error(message), { status }); }
function request(userId, body) {
  if (!validUuid(userId) || !body || typeof body !== 'object' || Array.isArray(body)
    || Object.keys(body).length !== 3 || !Object.hasOwn(body, 'workflowId') || !Object.hasOwn(body, 'expectedRevision')
    || !Object.hasOwn(body, 'confirm') || !validUuid(body.workflowId) || body.workflowId !== body.workflowId.toLowerCase()
    || !validRevision(body.expectedRevision) || body.confirm !== true) fail(400, 'Exact confirmed company offboarding request required');
  return userId.toLowerCase();
}
function receipt(row) {
  return { schemaVersion: 1, workflowId: row.workflow_id, tenantId: row.tenant_id, userId: row.user_id, actorUserId: row.actor_user_id,
    operationId: row.operation_id, action: row.action, beforeRevision: String(row.before_revision), afterRevision: String(row.after_revision),
    beforeEligibilityRevision: String(row.before_eligibility_revision), afterEligibilityRevision: String(row.after_eligibility_revision),
    createdAt: new Date(row.created_at).toISOString(), deliveryStatus: 'pending' };
}
class CompanyOffboarding {
  constructor(database, { issuer = process.env.OIDC_ISSUER || 'http://localhost:3001', revalidate = createTenantStateClient() } = {}) {
    this.database = database; this.options = { issuer, revalidate };
  }
  async receive(userId, body, user, authorization) {
    userId = request(userId, body);
    if (userId === user?.identity_authorization?.userId?.toLowerCase()) fail(403, 'Self offboarding is forbidden');
    const initial = await new CompanyLicenseAuthority(this.database, this.options).read(user, authorization, { userId });
    if (initial.target.deleted) fail(404, 'Own company account not found');
    let result;
    const validate = async client => {
      const bound = { isAvailable: () => true, transaction: operation => operation(client) };
      const source = await new CompanyLicenseAuthority(bound, this.options).read(user, authorization, { userId });
      if (!sameTenantContext(initial.tenant, source.tenant) || source.target.deleted) fail(401, 'Original company authority changed');
      await requireDirectoryPermissions(client, user, PERMISSIONS);
      return { bound, source };
    };
    return this.database.transaction(async client => {
      await client.query("SELECT pg_advisory_xact_lock(hashtextextended('identity-company-offboarding:'||$1||':'||$2,0))", [initial.tenant.id, body.workflowId]);
      await client.query('SELECT id FROM identity_tenants WHERE id=$1 FOR SHARE', [initial.tenant.id]);
      const ids = [initial.actorUserId, userId].sort();
      await client.query("SELECT id FROM users WHERE id=ANY($1::uuid[]) AND identity_tenant_id('user',id)=$2 ORDER BY id FOR UPDATE", [ids, initial.tenant.id]);
      const { bound, source } = await validate(client);
      await client.query('SELECT identity_company_offboarding_receiving()');
      const stored = (await client.query('SELECT * FROM identity_company_offboarding_receipts WHERE tenant_id=$1 AND workflow_id=$2', [source.tenant.id, body.workflowId])).rows[0];
      if (stored) {
        if (stored.user_id !== userId || String(stored.expected_revision) !== body.expectedRevision) fail(409, 'Company offboarding workflow request changed');
        result = receipt(stored);
      } else {
        const before = (await client.query("SELECT record_revision,eligibility_revision,enabled FROM users WHERE id=$1 AND identity_tenant_id('user',id)=$2", [userId, source.tenant.id])).rows[0];
        if (!before) fail(404, 'Own company account not found');
        if (String(before.record_revision) !== body.expectedRevision) fail(412, 'User changed; reload before offboarding');
        const operationId = before.enabled ? randomUUID() : null;
        const rolesSnapshot = (await client.query('SELECT identity_subject_link_role_state($1) AS state', [source.actorUserId])).rows[0].state;
        const proof = { issuer: source.issuer, subject: source.subject, context: source.context, tenant: source.tenant, rolesSnapshot,
          validUntil: source.validUntil, workflowId: body.workflowId, userId, expectedRevision: body.expectedRevision,
          operationId, beforeEligibilityRevision: String(before.eligibility_revision) };
        await client.query("SELECT set_config('opendirectory.company_offboarding',$1,true)", [JSON.stringify(proof)]);
        if (operationId) await new UserMutator(bound, { ...this.options, newOperationId: () => operationId })
          .update(userId, { enabled: false }, userEtag({ id: userId, revision: body.expectedRevision }), user, authorization);
        await validate(client);
        const inserted = await client.query(`INSERT INTO identity_company_offboarding_receipts
          (tenant_id,workflow_id,user_id,expected_revision,actor_user_id,operation_id,action,before_revision,after_revision,
           before_eligibility_revision,after_eligibility_revision,source)
          SELECT $1,$2,id,$3,$4,$5,$6,$3,record_revision,$7,eligibility_revision,$8::jsonb FROM users WHERE id=$9 RETURNING *`,
        [source.tenant.id, body.workflowId, body.expectedRevision, source.actorUserId, operationId, operationId ? 'disabled' : 'already_disabled',
          String(before.eligibility_revision), JSON.stringify(proof), userId]);
        if (inserted.rows.length !== 1) fail(503, 'Company offboarding receipt unavailable');
        result = receipt(inserted.rows[0]);
        await client.query(`INSERT INTO identity_company_offboarding_outbox(tenant_id,workflow_id,created_at)
          SELECT tenant_id,workflow_id,created_at FROM identity_company_offboarding_receipts WHERE tenant_id=$1 AND workflow_id=$2`, [source.tenant.id, body.workflowId]);
      }
      const final = await validate(client);
      const rolesSnapshot = (await client.query('SELECT identity_subject_link_role_state($1) AS state', [final.source.actorUserId])).rows[0].state;
      await client.query('SELECT identity_company_offboarding_check($1::jsonb)', [JSON.stringify({ issuer: final.source.issuer,
        subject: final.source.subject, context: final.source.context, tenant: final.source.tenant, rolesSnapshot, validUntil: final.source.validUntil,
        userId, workflowId: body.workflowId, expectedRevision: body.expectedRevision })]);
      await client.query('SELECT identity_company_offboarding_validate($1,$2,$3)', [initial.tenant.id, body.workflowId, userId]);
      return result;
    }, { actor: user.sub, beforeCommit: async client => {
      await validate(client);
      await client.query('SELECT identity_company_offboarding_validate($1,$2,$3)', [initial.tenant.id, body.workflowId, userId]);
    } });
  }
}
module.exports = { CompanyOffboarding };
