'use strict';

const { randomUUID, createHash } = require('crypto');
const { validUuid, sameContext } = require('../../../../packages/identity-authorization-contract');
const { sameTenantContext } = require('../../../../packages/tenant-authorization-contract');
const { groupCleanupQuery, groupCleanupValues } = require('../../../../packages/company-license-contract');
const { CompanyLicenseAuthority } = require('./CompanyLicenseAuthority');
const { requireDirectoryPermissions } = require('./DirectoryAuthority');
const { GroupMutator, groupEtag } = require('./GroupMutator');

function fail(status, message) { throw Object.assign(new Error(message), { status }); }
function targetId(value, user) {
  if (!validUuid(value)) fail(400, 'Canonical offboarding user required');
  value = value.toLowerCase();
  if (value === user?.identity_authorization?.userId?.toLowerCase()) fail(403, 'Self offboarding is forbidden');
  return value;
}
function statusCode(error) {
  return Number.isInteger(error.status) && error.status >= 400 && error.status <= 599 ? error.status
    : ({ '22P02': 400, '23503': 400, '23505': 409, '23514': 409, '42501': 403, '28000': 401 }[error.code] || 503);
}
function boundDatabase(client) {
  return { isAvailable: () => true, transaction: operation => operation(client) };
}
function historyReceipt(row) {
  return { id: row.id, groupId: row.group_id, name: row.name, membershipId: row.membership_id, operationId: row.operation_id,
    beforeGroupRevision: String(row.before_group_revision), afterGroupRevision: String(row.after_group_revision), actorUserId: row.actor_user_id,
    reason: row.reason, createdAt: new Date(row.created_at).toISOString(), deliveryStatus: 'pending' };
}

class CompanyOffboardingGroups {
  constructor(database, options = {}) { this.database = database; this.options = options; }

  async initial(userId, user, authorization) {
    const source = await new CompanyLicenseAuthority(this.database, this.options).read(user, authorization, { userId });
    if (source.target.deleted || source.target.enabled) fail(409, 'Retained disabled offboarding generation required');
    return source;
  }

  async validate(client, original, workflowId, userId, user, authorization, write) {
    const source = await new CompanyLicenseAuthority(boundDatabase(client), this.options).read(user, authorization, { userId });
    if (!sameContext(original.context, source.context) || !sameTenantContext(original.tenant, source.tenant)
      || source.issuer !== original.issuer || source.subject !== original.subject || source.actorUserId !== original.actorUserId
      || source.tokenId !== original.tokenId || source.expiresAt !== original.expiresAt || source.validUntil !== original.validUntil)
      fail(401, 'Original offboarding group authority changed');
    if (source.target.deleted || source.target.enabled || source.target.id !== userId
      || source.target.eligibilityRevision !== original.target.eligibilityRevision) fail(409, 'Original disabled offboarding generation changed');
    await requireDirectoryPermissions(client, user, write ? ['groups.read', 'groups.members.manage'] : ['groups.read']);
    await client.query('SELECT identity_company_offboarding_groups_receiving()');
    const parent = (await client.query('SELECT after_eligibility_revision FROM identity_company_offboarding_receipts WHERE tenant_id=$1 AND workflow_id=$2 AND user_id=$3',
      [original.tenant.id, workflowId, userId])).rows[0];
    if (!parent || String(parent.after_eligibility_revision) !== original.target.eligibilityRevision) fail(409, 'Exact disabled parent account receipt required');
    await client.query('SELECT identity_company_offboarding_validate($1,$2,$3)', [original.tenant.id, workflowId, userId]);
    return source;
  }

  async retained(client, original, workflowId, userId, member) {
    const row = (await client.query(`SELECT * FROM identity_company_offboarding_group_receipts
      WHERE tenant_id=$1 AND workflow_id=$2 AND user_id=$3 AND membership_id=$4`,
    [original.tenant.id, workflowId, userId, member.membershipId])).rows[0];
    if (!row) return null;
    if (row.group_id !== member.groupId || String(row.before_group_revision) !== member.groupRevision) fail(412, 'Original captured group version required');
    await client.query('SELECT identity_company_offboarding_group_validate($1)', [row.id]);
    return row;
  }

  async membership(client, original, userId, member) {
    const group = (await client.query("SELECT id,revision FROM groups WHERE id=$1 AND identity_tenant_id('group',id)=$2", [member.groupId, original.tenant.id])).rows[0];
    if (!group) fail(404, 'Own company group not found');
    if (String(group.revision) !== member.groupRevision) fail(412, 'Captured group version changed');
    const link = (await client.query('SELECT membership_id FROM group_members WHERE group_id=$1 AND user_id=$2 AND membership_id=$3',
      [member.groupId, userId, member.membershipId])).rows[0];
    if (!link) fail(409, 'Captured membership incarnation changed');
  }

  async read(kind, userId, query, user, authorization) {
    const { workflowId, page, limit } = groupCleanupQuery(query); userId = targetId(userId, user);
    const original = await this.initial(userId, user, authorization);
    const validate = client => this.validate(client, original, workflowId, userId, user, authorization, false);
    const result = await this.database.transaction(async client => {
      await validate(client);
      const base = { schemaVersion: 1, ...(kind === 'preview' ? { companyOffboardingGroupsProtocol: 1 } : {}),
        actorUserId: original.actorUserId, tenantId: original.tenant.id, workflowId, userId,
        target: { enabled: false, eligibilityRevision: original.target.eligibilityRevision } };
      if (kind === 'preview') {
        if ((await client.query(`SELECT 1 FROM group_members link LEFT JOIN groups collection ON collection.id=link.group_id
          WHERE link.user_id=$1 AND (collection.id IS NULL OR identity_tenant_id('group',collection.id) IS DISTINCT FROM $2::uuid) LIMIT 1`, [userId, original.tenant.id])).rows.length)
          fail(503, 'Incoherent company group membership');
        const total = Number((await client.query(`SELECT count(*) AS count FROM group_members link JOIN groups collection ON collection.id=link.group_id
          WHERE link.user_id=$1 AND identity_tenant_id('group',collection.id)=$2`, [userId, original.tenant.id])).rows[0].count);
        const rows = (await client.query(`SELECT collection.id,collection.name,collection.revision,link.membership_id FROM group_members link
          JOIN groups collection ON collection.id=link.group_id WHERE link.user_id=$1 AND identity_tenant_id('group',collection.id)=$2
          ORDER BY collection.id LIMIT $3 OFFSET $4`, [userId, original.tenant.id, limit, (page - 1) * limit])).rows;
        return { ...base, groups: rows.map(row => ({ groupId: row.id, name: row.name, groupRevision: String(row.revision), membershipId: row.membership_id })), total, page, limit };
      }
      const total = Number((await client.query('SELECT count(*) AS count FROM identity_company_offboarding_group_receipts WHERE tenant_id=$1 AND workflow_id=$2 AND user_id=$3',
        [original.tenant.id, workflowId, userId])).rows[0].count);
      const rows = (await client.query(`SELECT * FROM identity_company_offboarding_group_receipts WHERE tenant_id=$1 AND workflow_id=$2 AND user_id=$3
        ORDER BY created_at,id LIMIT $4 OFFSET $5`, [original.tenant.id, workflowId, userId, limit, (page - 1) * limit])).rows;
      for (const row of rows) await client.query('SELECT identity_company_offboarding_group_validate($1)', [row.id]);
      return { ...base, receipts: rows.map(historyReceipt), total, page, limit };
    }, { readOnly: true, beforeCommit: validate });
    await this.database.transaction(validate, { readOnly: true });
    return result;
  }

  preview(userId, query, user, authorization) { return this.read('preview', userId, query, user, authorization); }
  history(userId, query, user, authorization) { return this.read('history', userId, query, user, authorization); }

  async remove(userId, body, user, authorization) {
    const intent = groupCleanupValues(body); userId = targetId(userId, user);
    const original = await this.initial(userId, user, authorization);
    if (intent.eligibilityRevision !== original.target.eligibilityRevision) fail(409, 'Captured disabled eligibility generation changed');
    const validate = client => this.validate(client, original, intent.workflowId, userId, user, authorization, true);
    const rolesSnapshot = await this.database.transaction(async client => {
      await validate(client);
      for (const member of intent.memberships) {
        if (!await this.retained(client, original, intent.workflowId, userId, member)) await this.membership(client, original, userId, member);
      }
      return (await client.query('SELECT identity_subject_link_role_state($1) AS state', [original.actorUserId])).rows[0].state;
    }, { readOnly: true, beforeCommit: validate });
    const correlationId = randomUUID(); const results = []; let stopped = false;
    for (const member of intent.memberships) {
      if (stopped) { results.push({ groupId: member.groupId, membershipId: member.membershipId, status: 'not_attempted', code: null, operationId: null }); continue; }
      try {
        const row = await this.database.transaction(async client => {
          await client.query('SELECT id FROM identity_tenants WHERE id=$1 FOR SHARE', [original.tenant.id]);
          await client.query("SELECT id FROM users WHERE id=ANY($1::uuid[]) AND identity_tenant_id('user',id)=$2 ORDER BY id FOR UPDATE",
            [[original.actorUserId, userId].sort(), original.tenant.id]);
          await validate(client);
          const stored = await this.retained(client, original, intent.workflowId, userId, member);
          await client.query("SELECT id FROM groups WHERE id=$1 AND identity_tenant_id('group',id)=$2 FOR UPDATE", [member.groupId, original.tenant.id]);
          if (!stored) await this.membership(client, original, userId, member);
          const operationId = stored?.operation_id || randomUUID(); const receiptId = stored?.id || randomUUID();
          const proof = { issuer: original.issuer, subject: original.subject, context: original.context, tenant: original.tenant, rolesSnapshot,
            validUntil: original.validUntil, tokenSha256: createHash('sha256').update(authorization).digest('hex'),
            workflowId: intent.workflowId, userId, eligibilityRevision: intent.eligibilityRevision, ...member,
            operationId, receiptId, correlationId, reason: intent.reason, recovery: !!stored };
          await client.query('SELECT identity_company_offboarding_groups_begin($1::jsonb)', [JSON.stringify(proof)]);
          if (stored) return { status: 'already_removed', operationId };
          await new GroupMutator(boundDatabase(client), { ...this.options, newOperationId: () => operationId })
            .removeMember(member.groupId, userId, groupEtag({ id: member.groupId, revision: member.groupRevision }), user, authorization);
          await validate(client);
          const inserted = await client.query(`INSERT INTO identity_company_offboarding_group_receipts
            (id,tenant_id,workflow_id,user_id,group_id,membership_id,before_group_revision,after_group_revision,operation_id,actor_user_id,
             correlation_id,reason,name,eligibility_revision,source,child_proof,child_after,valid_until)
            SELECT $1,$2,$3,$4,$5,$6,$7,(event.details->>'afterRevision')::bigint,event.id,$8,$9,$10,
              current_setting('opendirectory.group_mutation')::jsonb#>>'{target,before,name}',$11,$12::jsonb,
              current_setting('opendirectory.group_mutation')::jsonb,identity_directory_group_validate(current_setting('opendirectory.group_mutation')::jsonb),to_timestamp($13)
            FROM identity_directory_group_events event WHERE event.id=$14 RETURNING id`,
          [receiptId, original.tenant.id, intent.workflowId, userId, member.groupId, member.membershipId, member.groupRevision,
            original.actorUserId, correlationId, intent.reason, intent.eligibilityRevision, JSON.stringify(proof), original.validUntil, operationId]);
          if (inserted.rows.length !== 1) fail(503, 'Actual offboarding group receipt unavailable');
          await client.query(`INSERT INTO identity_company_offboarding_group_outbox(id,tenant_id,created_at)
            SELECT id,tenant_id,created_at FROM identity_company_offboarding_group_receipts WHERE id=$1`, [receiptId]);
          await client.query('SELECT identity_company_offboarding_group_validate($1)', [receiptId]);
          return { status: 'removed', operationId };
        }, { actor: user.sub, beforeCommit: validate });
        results.push({ groupId: member.groupId, membershipId: member.membershipId, status: row.status, code: 200, operationId: row.operationId });
      } catch (error) {
        await this.database.transaction(validate, { readOnly: true });
        results.push({ groupId: member.groupId, membershipId: member.membershipId, status: 'unconfirmed', code: statusCode(error), operationId: null });
        stopped = true;
      }
    }
    await this.database.transaction(validate, { readOnly: true });
    return { schemaVersion: 1, actorUserId: original.actorUserId, tenantId: original.tenant.id, workflowId: intent.workflowId, userId, correlationId, results };
  }
}

module.exports = { CompanyOffboardingGroups };
