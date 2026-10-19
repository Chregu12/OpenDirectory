'use strict';

const { validContext, validUuid } = require('../../../../packages/identity-authorization-contract');
const { acceptsRoleAuthentication } = require('../../../../packages/role-authentication-contract');
const { getIdentityPermissions } = require('./middleware/identityAccess');
const { authorityTenant } = require('./AuthorityTenant');
const { readRoleState } = require('./RoleState');
const { AuthorityCommand } = require('./AuthorityCommand');
const { companyOwner } = require('./CompanyOwner');

const PERMISSIONS = ['organization.read', 'organization.manage'];
function fail(status, code, cause) { throw Object.assign(new Error(code, cause ? { cause } : undefined), { status, code }); }
function actorProof(user) {
  if (user?.actor_type !== 'user' || !validContext(user.identity_authorization) || typeof user.iss !== 'string' || !user.iss || typeof user.sub !== 'string' || !user.sub) fail(403, 'canonical_human_required');
  return { ...user.identity_authorization, issuer: user.iss, subject: user.sub };
}
function commandBody(body, grant) {
  const fields = grant ? ['userId', 'durationSeconds', 'reason'] : ['reason'];
  if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).length !== fields.length || fields.some(field => !Object.hasOwn(body, field))
    || typeof body.reason !== 'string' || body.reason.trim().length < 10 || body.reason.length > 500 || /[\u0000-\u001f\u007f]/u.test(body.reason)
    || grant && (!validUuid(body.userId) || body.userId !== body.userId.toLowerCase() || !Number.isInteger(body.durationSeconds) || body.durationSeconds < 60 || body.durationSeconds > 28800)) fail(400, 'invalid_organization_delegation');
  return { ...body, reason: body.reason.trim() };
}
function delegationError(error) {
  if (error.code === '23503') fail(404, 'organization_target_not_found');
  if (error.code === '23505') fail(409, 'organization_delegation_changed');
  if (error.code === '23514') fail(400, 'invalid_organization_delegation');
  if (error.code === '42501') fail(503, 'organization_delegation_unavailable', error);
  throw error;
}
async function delegationFor(client, user) {
  const proof = actorProof(user); const tenant = await authorityTenant(client, proof);
  await client.query('SELECT identity_organization_delegation_receiving()');
  const rows = (await client.query(`SELECT grant_row.id,grant_row.expires_at,identity_organization_delegation_evidence(grant_row.id) AS evidence
    FROM identity_organization_delegations grant_row WHERE grant_row.user_id=$1 AND grant_row.tenant_id=$2 AND grant_row.expires_at>clock_timestamp()
    AND NOT EXISTS(SELECT 1 FROM identity_organization_delegation_revocations revoked WHERE revoked.grant_id=grant_row.id) ORDER BY grant_row.id LIMIT 2`, [proof.userId, tenant])).rows;
  if (rows.length > 1 || rows.some(row => row.evidence !== true)) fail(503, 'organization_delegation_unavailable');
  return rows[0] || null;
}
class OrganizationDelegations {
  constructor(database, options = {}) { this.database = database; this.commands = new AuthorityCommand(database, options); }
  async permissions(user) {
    if (user?.actor_type !== 'user' || !validContext(user.identity_authorization)) return [];
    return this.database.transaction(async client => await companyOwner(client, user) ? [...PERMISSIONS, 'organization.delegations.manage'] : getIdentityPermissions(user).includes('organization.manage') ? [] : await delegationFor(client, user) ? PERMISSIONS : [], { readOnly: true }).catch(delegationError);
  }
  async context(client, user) {
    const proof = actorProof(user);
    const owner = await companyOwner(client, user);
    if (!getIdentityPermissions(user).includes('organization.delegations.manage') && !owner) fail(403, 'forbidden');
    await client.query("SET LOCAL timezone='UTC'");
    const tenantId = await authorityTenant(client, proof); const state = await readRoleState(client, proof.userId);
    if (state.rolesRevision !== proof.rolesRevision || !owner && !getIdentityPermissions({ roles: state.roles }).includes('organization.delegations.manage')) fail(401, 'organization_actor_changed');
    if (!acceptsRoleAuthentication(state.authentication, user)) fail(428, 'fresh_mfa_required');
    await client.query('SELECT identity_organization_delegation_receiving()'); return tenantId;
  }
  async list(user) {
    user = structuredClone(user);
    return this.database.transaction(async client => {
      const tenantId = await this.context(client, user);
      const rows = (await client.query(`SELECT grant_row.*,account.username,account.display_name,account.enabled,revoked.grant_id IS NOT NULL AS revoked,
        grant_row.expires_at>clock_timestamp() AS unexpired,identity_organization_delegation_evidence(grant_row.id) AS evidence
        FROM identity_organization_delegations grant_row JOIN users account ON account.id=grant_row.user_id
        LEFT JOIN identity_organization_delegation_revocations revoked ON revoked.grant_id=grant_row.id WHERE grant_row.tenant_id=$1
        ORDER BY grant_row.created_at DESC,grant_row.id DESC LIMIT 101`, [tenantId])).rows;
      if (rows.some(row => row.evidence !== true)) fail(503, 'organization_delegation_unavailable');
      return { schemaVersion: 1, actorUserId: user.identity_authorization.userId, tenantId, permissions: PERMISSIONS, canManage: acceptsRoleAuthentication({ required: true, maxAgeSeconds: 300 }, user),
        truncated: rows.length > 100, grants: rows.slice(0, 100).map(row => ({ id: row.id, userId: row.user_id, username: row.username, name: row.display_name || row.username,
          expiresAt: row.expires_at.toISOString(), createdAt: row.created_at.toISOString(), status: row.revoked ? 'revoked' : !row.enabled ? 'inactive' : row.unexpired ? 'active' : 'expired' })) };
    }, { readOnly: true }).catch(delegationError);
  }
  async change(action, identifier, values, user, authorization) {
    user = structuredClone(user); const proof = actorProof(user); const body = commandBody(values, action === 'granted');
    if (!['granted', 'revoked'].includes(action) || !validUuid(identifier) || action === 'granted' && identifier !== body.userId) fail(400, 'invalid_organization_delegation');
    if (!acceptsRoleAuthentication({ required: true, maxAgeSeconds: 300 }, user)) fail(428, 'fresh_mfa_required');
    return this.commands.run(user, authorization, async client => {
      const tenantId = await this.context(client, user);
      const eventId = (await client.query('SELECT identity_organization_delegation_change($1::jsonb,$2,$3,$4::uuid,$5::int,$6,$7::bigint) AS id',
        [JSON.stringify(proof), user.jti, action, identifier, body.durationSeconds ?? null, body.reason, String(Math.min(user.exp, user.auth_time + 300))])).rows[0]?.id;
      const event = (await client.query(`SELECT event.*,identity_organization_delegation_evidence(event.grant_id) AS evidence FROM identity_organization_delegation_events event
        WHERE event.id=$1 AND event.tenant_id=$2 AND event.transaction_id=txid_current() AND event.actor=$3::jsonb`, [eventId, tenantId, JSON.stringify(proof)])).rows[0];
      if (!event || event.evidence !== true || event.action !== action || (action === 'granted' ? event.user_id : event.grant_id) !== identifier) fail(503, 'organization_delegation_unavailable');
      return { schemaVersion: 1, actorUserId: proof.userId, tenantId, eventId, grantId: event.grant_id, userId: event.user_id, action, expiresAt: event.expires_at.toISOString() };
    }, { actor: JSON.stringify(proof) }, { required: true, maxAgeSeconds: 300 }).catch(delegationError);
  }
}
module.exports = { OrganizationDelegations, delegationFor, commandBody };
