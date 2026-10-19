'use strict';

const { randomUUID, createHash } = require('node:crypto');
const { validUuid, sameContext } = require('../../../../packages/identity-authorization-contract');
const { sameTenantContext } = require('../../../../packages/tenant-authorization-contract');
const { accessCleanupCapabilitiesQuery, accessCleanupQuery, accessCleanupValues } = require('../../../../packages/company-license-contract');
const { PROTECTED, ROLES } = require('../../../../packages/directory-role-contract');
const { CompanyOffboardingAccessAuthority } = require('./CompanyOffboardingAccessAuthority');
const { DirectoryRoles } = require('./DirectoryRoles');
const { PrivilegedActivation } = require('./PrivilegedActivation');
function fail(status, message) { throw Object.assign(new Error(message), { status }); }
const duty = (kind, write = false) => (kind === 'role' ? 'identities.roles.' : 'pim.eligibilities.') + (write ? 'manage' : 'read');
const table = kind => kind === 'role' ? 'identity_role_assignments' : 'identity_pim_eligibilities';
const boundDatabase = client => ({ isAvailable: () => true, transaction: operation => operation(client) });
const supportedKinds = source => ['role', 'eligibility'].filter(kind => source.permissions.includes(duty(kind)));
function statusCode(error) {
  return Number.isInteger(error.status) && error.status >= 400 && error.status <= 599 ? error.status
    : ({ '22P02': 400, '23503': 400, '23505': 409, '23514': 409, '42501': 403, '28000': 401 }[error.code] || 503);
}
function targetId(value, user) {
  if (!validUuid(value)) fail(400, 'Canonical offboarding user required');
  value = value.toLowerCase();
  if (value === user?.identity_authorization?.userId?.toLowerCase()) fail(403, 'Self access cleanup is forbidden');
  return value;
}
function blockedReason(source, kind, role) {
  if (!source.permissions.includes(duty(kind, true))) return 'permission_required';
  return PROTECTED.includes(role) && !source.roles.includes('admin') ? 'protected_role' : null;
}
function receiptView(row) {
  return { id: row.id, resourceId: row.resource_id, role: row.role, version: row.version, kind: row.kind, checkpointId: row.checkpoint_id,
    actorUserId: row.actor_user_id, correlationId: row.correlation_id, reason: row.reason, createdAt: new Date(row.created_at).toISOString(), deliveryStatus: 'pending' };
}

class CompanyOffboardingAccess {
  constructor(database, options = {}) { this.database = database; this.options = options; }
  initial(user, authorization) { return new CompanyOffboardingAccessAuthority(this.database, this.options).read(user, authorization); }
  async validate(client, original, workflowId, userId, kind, user, authorization, write = false) {
    const source = await new CompanyOffboardingAccessAuthority(boundDatabase(client), this.options).read(user, authorization);
    if (!sameContext(original.context, source.context) || !sameTenantContext(original.tenant, source.tenant)
      || source.issuer !== original.issuer || source.subject !== original.subject || source.actorUserId !== original.actorUserId
      || source.tokenId !== original.tokenId || source.expiresAt !== original.expiresAt || source.validUntil !== original.validUntil) fail(401, 'Original access cleanup authority changed');
    if (kind ? !source.permissions.includes(duty(kind)) || write && !source.permissions.includes(duty(kind, true)) : !supportedKinds(source).length)
      fail(403, 'Actual access cleanup permission required');
    await client.query("SET LOCAL timezone='UTC'");
    await client.query('SELECT identity_company_offboarding_access_receiving()');
    const target = (await client.query(`SELECT account.id,account.enabled,account.eligibility_revision,parent.after_eligibility_revision
      FROM users account JOIN identity_company_offboarding_receipts parent ON parent.user_id=account.id
      WHERE account.id=$1 AND parent.tenant_id=$2 AND parent.workflow_id=$3 AND identity_tenant_id('user',account.id)=$2`, [userId, original.tenant.id, workflowId])).rows[0];
    if (!target || target.enabled !== false || String(target.eligibility_revision) !== String(target.after_eligibility_revision)) fail(409, 'Exact retained disabled parent account receipt required');
    await client.query('SELECT identity_company_offboarding_validate($1,$2,$3)', [original.tenant.id, workflowId, userId]);
    return { source, target: { enabled: false, eligibilityRevision: String(target.eligibility_revision) } };
  }
  async read(mode, userId, query, user, authorization) {
    const selectors = mode === 'capabilities' ? accessCleanupCapabilitiesQuery(query) : accessCleanupQuery(query);
    const { workflowId, kind, page, limit } = selectors; userId = targetId(userId, user);
    const original = await this.initial(user, authorization);
    const validate = client => this.validate(client, original, workflowId, userId, kind, user, authorization);
    const result = await this.database.transaction(async client => {
      const { source, target } = await validate(client);
      const base = { schemaVersion: 1, ...(mode !== 'history' ? { companyOffboardingAccessProtocol: 1 } : {}),
        actorUserId: original.actorUserId, tenantId: original.tenant.id, workflowId, userId, target };
      if (mode === 'capabilities') return { ...base, permissions: source.permissions, supportedKinds: supportedKinds(source) };
      if (mode === 'preview') {
        const total = Number((await client.query(`SELECT count(*) AS count FROM ${table(kind)} WHERE user_id=$1 AND revoked_at IS NULL`, [userId])).rows[0].count);
        const rows = (await client.query(`SELECT grant_row.*,encode(sha256(convert_to(to_jsonb(grant_row)::text,'UTF8')),'hex') AS version
          FROM ${table(kind)} grant_row WHERE user_id=$1 AND revoked_at IS NULL ORDER BY created_at,id LIMIT $2 OFFSET $3`, [userId, limit, (page - 1) * limit])).rows;
        return { ...base, kind, canRevoke: source.permissions.includes(duty(kind, true)), items: rows.map(row => {
          if (!ROLES.includes(row.role)) fail(503, 'Canonical access grant catalog required');
          const blocked = blockedReason(source, kind, row.role);
          return { id: row.id, role: row.role, version: row.version, createdAt: new Date(row.created_at).toISOString(),
            expiresAt: row.expires_at ? new Date(row.expires_at).toISOString() : null, canRevoke: !blocked, blockedReason: blocked };
        }), total, page, limit };
      }
      const parameters = [original.tenant.id, workflowId, userId, kind];
      const total = Number((await client.query('SELECT count(*) AS count FROM identity_company_offboarding_access_receipts WHERE tenant_id=$1 AND workflow_id=$2 AND user_id=$3 AND kind=$4', parameters)).rows[0].count);
      const rows = (await client.query(`SELECT * FROM identity_company_offboarding_access_receipts WHERE tenant_id=$1 AND workflow_id=$2 AND user_id=$3 AND kind=$4
        ORDER BY created_at,id LIMIT $5 OFFSET $6`, [...parameters, limit, (page - 1) * limit])).rows;
      for (const row of rows) await client.query('SELECT identity_company_offboarding_access_validate($1)', [row.id]);
      return { ...base, kind, receipts: rows.map(receiptView), total, page, limit };
    }, { readOnly: true, beforeCommit: validate });
    await this.database.transaction(validate, { readOnly: true });
    return result;
  }
  capabilities(userId, query, user, authorization) { return this.read('capabilities', userId, query, user, authorization); }
  preview(userId, query, user, authorization) { return this.read('preview', userId, query, user, authorization); }
  history(userId, query, user, authorization) { return this.read('history', userId, query, user, authorization); }
  async retained(client, source, intent, userId, item) {
    const row = (await client.query(`SELECT * FROM identity_company_offboarding_access_receipts
      WHERE tenant_id=$1 AND workflow_id=$2 AND user_id=$3 AND kind=$4 AND resource_id=$5`, [source.tenant.id, intent.workflowId, userId, intent.kind, item.id])).rows[0];
    if (!row) return null;
    if (row.version !== item.version) fail(412, 'Original captured access version required');
    await client.query('SELECT identity_company_offboarding_access_validate($1)', [row.id]);
    if (blockedReason(source, intent.kind, row.role)) fail(403, 'Actual protected access revocation permission required');
    return row;
  }
  async capture(client, source, intent, userId, item) {
    const captured = (await client.query(`SELECT graph,identity_authority_hash(graph->'grant') AS version
      FROM (SELECT identity_company_offboarding_access_capture($1,$2,$3,$4) AS graph) captured`, [intent.kind, item.id, userId, source.tenant.id])).rows[0];
    const graph = captured?.graph;
    if (!graph?.grant) fail(404, 'Own captured access grant not found');
    const row = graph.grant;
    if (captured.version !== item.version) fail(412, 'Captured access version changed');
    if (row.revoked_at) fail(409, 'Access grant already revoked outside this cleanup');
    if (!ROLES.includes(row.role)) fail(503, 'Canonical access grant catalog required');
    if (blockedReason(source, intent.kind, row.role)) fail(403, 'Actual protected access revocation permission required');
    return graph;
  }
  async revoke(userId, body, user, authorization) {
    const intent = accessCleanupValues(body); userId = targetId(userId, user); user = structuredClone(user);
    const original = await this.initial(user, authorization);
    const validate = async client => {
      const result = await this.validate(client, original, intent.workflowId, userId, intent.kind, user, authorization, true);
      if (result.target.eligibilityRevision !== intent.eligibilityRevision) fail(409, 'Captured disabled eligibility generation changed');
      return result;
    };
    await this.database.transaction(async client => {
      await validate(client);
      for (const item of intent.items) if (!await this.retained(client, original, intent, userId, item)) await this.capture(client, original, intent, userId, item);
    }, { readOnly: true, beforeCommit: validate });
    const correlationId = randomUUID(); const results = []; let stopped = false;
    for (const item of intent.items) {
      if (stopped) { results.push({ id: item.id, status: 'not_attempted', code: null, checkpointId: null }); continue; }
      try {
        const result = await this.database.transaction(async client => {
          await client.query('SELECT id FROM identity_tenants WHERE id=$1 FOR SHARE', [original.tenant.id]);
          await client.query("SELECT id FROM users WHERE id=ANY($1::uuid[]) AND identity_tenant_id('user',id)=$2 ORDER BY id FOR UPDATE", [[original.actorUserId, userId].sort(), original.tenant.id]);
          await validate(client);
          const retained = await this.retained(client, original, intent, userId, item);
          if (!retained) await this.capture(client, original, intent, userId, item);
          const rolesSnapshot = (await client.query('SELECT identity_subject_link_role_state($1) AS state', [original.actorUserId])).rows[0].state;
          const proof = { issuer: original.issuer, subject: original.subject, context: original.context, tenant: original.tenant, rolesSnapshot,
            validUntil: original.validUntil, authTime: user.auth_time, tokenSha256: createHash('sha256').update(authorization).digest('hex'),
            tokenIdSha256: createHash('sha256').update(JSON.stringify(user.jti)).digest('hex'), workflowId: intent.workflowId, userId,
            eligibilityRevision: intent.eligibilityRevision, kind: intent.kind, resourceId: item.id, version: item.version,
            receiptId: retained?.id || randomUUID(), correlationId, reason: intent.reason, recovery: !!retained };
          await client.query('SELECT identity_company_offboarding_access_begin($1::jsonb)', [JSON.stringify(proof)]);
          if (retained) return { status: 'already_revoked', checkpointId: retained.checkpoint_id };
          let checkpointId = null;
          const childClient = { query: async (sql, parameters) => {
            if (sql.startsWith('SELECT identity_authority_command_checkpoint(')) {
              if (checkpointId) fail(503, 'One actual canonical child checkpoint required');
              checkpointId = parameters[0];
              await client.query('SELECT identity_company_offboarding_access_finish($1,$2)', [checkpointId, JSON.stringify(proof)]);
            }
            return client.query(sql, parameters);
          } };
          const child = boundDatabase(childClient);
          const options = { revalidate: async (claims, bearer) => {
            if (bearer !== authorization || !sameContext(claims.identity_authorization, original.context) || claims.jti !== original.tokenId || claims.exp !== original.expiresAt) fail(401, 'Original child bearer required');
            await validate(client);
          } };
          if (intent.kind === 'role') await new DirectoryRoles(child, options).revoke(userId, item.id, user, authorization);
          else await new PrivilegedActivation(child, options).revokeEligibility(item.id, user, authorization);
          if (!checkpointId) fail(503, 'Actual canonical child checkpoint unavailable');
          await validate(client);
          await client.query('SELECT identity_company_offboarding_access_validate($1)', [proof.receiptId]);
          return { status: 'revoked', checkpointId };
        }, { actor: JSON.stringify({ issuer: original.issuer, subject: original.subject, userId: original.actorUserId }), beforeCommit: validate });
        results.push({ id: item.id, status: result.status, code: 200, checkpointId: result.checkpointId });
      } catch (error) {
        await this.database.transaction(validate, { readOnly: true });
        results.push({ id: item.id, status: 'unconfirmed', code: statusCode(error), checkpointId: null }); stopped = true;
      }
    }
    await this.database.transaction(validate, { readOnly: true });
    return { schemaVersion: 1, actorUserId: original.actorUserId, tenantId: original.tenant.id, workflowId: intent.workflowId, userId, kind: intent.kind, correlationId, results };
  }
}
module.exports = { CompanyOffboardingAccess };
