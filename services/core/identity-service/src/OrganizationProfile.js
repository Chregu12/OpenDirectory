'use strict';

const { normalizeProfile, organizationEtag } = require('../../../../packages/organization-profile-contract');
const { validContext } = require('../../../../packages/identity-authorization-contract');
const { acceptsRoleAuthentication } = require('../../../../packages/role-authentication-contract');
const { getIdentityPermissions } = require('./middleware/identityAccess');
const { authorityTenant } = require('./AuthorityTenant');
const { readRoleState } = require('./RoleState');
const { AuthorityCommand } = require('./AuthorityCommand');
const { delegationFor } = require('./OrganizationDelegations');
const { companyOwner } = require('./CompanyOwner');

function fail(status, code) { throw Object.assign(new Error(code), { status, code }); }
function proof(user) {
  if (user?.actor_type !== 'user' || !validContext(user.identity_authorization) || typeof user.iss !== 'string' || !user.iss || typeof user.sub !== 'string' || !user.sub) fail(403, 'canonical_human_required');
  return { ...user.identity_authorization, issuer: user.iss, subject: user.sub };
}
function organizationError(error) {
  if (['40001', '23505'].includes(error.code)) fail(412, 'organization_changed');
  if (error.code === '23514') fail(400, 'invalid_organization_profile');
  if (error.code === '42501') fail(503, 'organization_receiving_unavailable');
  throw error;
}
class OrganizationProfile {
  constructor(database, options = {}) { this.database = database; this.commands = new AuthorityCommand(database, options); }

  async context(client, user, permission) {
    await client.query("SET LOCAL timezone='UTC'");
    const original = proof(user);
    const owner = await companyOwner(client, user);
    const delegation = getIdentityPermissions(user).includes(permission) || owner ? null : await delegationFor(client, user);
    if (!getIdentityPermissions(user).includes(permission) && !delegation && !owner) fail(403, 'forbidden');
    const tenantId = await authorityTenant(client, original);
    const state = await readRoleState(client, original.userId);
    if (state.rolesRevision !== original.rolesRevision || !delegation && !owner && !getIdentityPermissions({ roles: state.roles }).includes(permission)) fail(401, 'organization_actor_changed');
    if (!acceptsRoleAuthentication(state.authentication, user)) fail(428, 'fresh_mfa_required');
    if (delegation && !acceptsRoleAuthentication({ required: true, maxAgeSeconds: 300 }, user)) fail(428, 'fresh_mfa_required');
    await client.query('SELECT identity_organization_receiving()');
    const tenant = (await client.query('SELECT id,display_name,version,generation FROM identity_tenants WHERE id=$1 AND enabled', [tenantId])).rows[0];
    return { ...tenant, delegationDeadline: delegation ? Math.floor(delegation.expires_at.getTime() / 1000) : null };
  }

  async view(client, user, tenant) {
    const row = (await client.query('SELECT profile.*,identity_organization_profile_data(profile) AS data FROM identity_organization_profiles profile WHERE tenant_id=$1', [tenant.id])).rows[0];
    if (row) {
      const receipt = await client.query(`SELECT event.id FROM identity_organization_profiles profile JOIN identity_organization_events event ON event.id=profile.command_id
        JOIN identity_organization_outbox outbox ON outbox.id=event.id WHERE profile.tenant_id=$1 AND event.tenant_id=profile.tenant_id AND event.after_state=to_jsonb(profile)
        AND outbox.tenant_id=event.tenant_id AND outbox.action=event.action AND outbox.status='pending' AND outbox.created_at=event.created_at`, [tenant.id]);
      if (receipt.rows.length !== 1 || receipt.rows[0].id !== row.command_id) fail(503, 'organization_receipt_unavailable');
    }
    const owner = { id: tenant.id, name: tenant.display_name, version: String(tenant.version), generation: String(tenant.generation) };
    const fresh = acceptsRoleAuthentication({ required: true, maxAgeSeconds: 300 }, user);
    const allowed = getIdentityPermissions(user).includes('organization.manage') || !!await companyOwner(client, user) || !!await delegationFor(client, user);
    return { schemaVersion: 1, actorUserId: user.identity_authorization.userId, tenant: owner, organization: row ? {
      id: row.id, version: String(row.version), ...normalizeProfile(row.data), createdAt: row.created_at.toISOString(), updatedAt: row.updated_at.toISOString(),
    } : null, etag: organizationEtag(owner, row ? String(row.version) : '0'), canManage: allowed && fresh, requiresFreshMfa: allowed && !fresh, verificationSupported: false };
  }

  async get(user) {
    const original = structuredClone(user);
    return this.database.transaction(async client => this.view(client, original, await this.context(client, original, 'organization.read')), { readOnly: true }).catch(organizationError);
  }

  async save(body, etag, user, authorization) {
    user = structuredClone(user);
    const actor = proof(user);
    if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).length !== 2 || !Object.hasOwn(body, 'profile') || !Object.hasOwn(body, 'reason')
      || typeof body.reason !== 'string' || body.reason.trim().length < 10 || body.reason.length > 500 || /[\u0000-\u001f\u007f]/u.test(body.reason)) fail(400, 'invalid_organization_profile');
    const profile = normalizeProfile(body.profile);
    const reason = body.reason.trim();
    if (typeof etag !== 'string' || !etag) fail(428, 'organization_version_required');
    if (!acceptsRoleAuthentication({ required: true, maxAgeSeconds: 300 }, user)) fail(428, 'fresh_mfa_required');
    return this.commands.run(user, authorization, async client => {
      const tenant = await this.context(client, user, 'organization.manage');
      await this.view(client, user, tenant);
      const result = await client.query('SELECT identity_organization_save($1::jsonb,$2,$3,$4::jsonb,$5,$6::bigint) AS command_id',
        [JSON.stringify(actor), user.jti, etag, JSON.stringify(profile), reason, String(Math.min(user.exp, user.auth_time + 300, tenant.delegationDeadline ?? Infinity))]);
      const commandId = result.rows[0]?.command_id;
      const receipt = await client.query(`SELECT event.id FROM identity_organization_events event JOIN identity_organization_outbox outbox USING(id)
        JOIN identity_organization_profiles profile ON profile.command_id=event.id WHERE event.id=$1 AND event.transaction_id=txid_current() AND event.tenant_id=$2
        AND event.actor=$3::jsonb AND event.after_state=to_jsonb(profile) AND outbox.tenant_id=event.tenant_id AND outbox.status='pending' AND outbox.action=event.action AND outbox.created_at=event.created_at`,
      [commandId, tenant.id, JSON.stringify(actor)]);
      if (!commandId || receipt.rows.length !== 1 || receipt.rows[0].id !== commandId) fail(503, 'organization_receipt_unavailable');
      return this.view(client, user, tenant);
    }, { actor: JSON.stringify(actor) }, { required: true, maxAgeSeconds: 300 }).catch(organizationError);
  }
}

module.exports = { OrganizationProfile };
