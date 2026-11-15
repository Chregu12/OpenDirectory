'use strict';
const { isDeepStrictEqual } = require('node:util');
const { sameContext } = require('../../../../packages/identity-authorization-contract');
const { sameTenantContext } = require('../../../../packages/tenant-authorization-contract');
const { createTenantStateClient } = require('../../../../packages/oidc-tenant-state');
const { acceptsRoleAuthentication } = require('../../../../packages/role-authentication-contract');
const C = require('../../../../packages/device-ou-retirement-contract');
const { fail } = require('../../../../packages/device-ou-contract');
const { AuthorizationState } = require('./AuthorizationState');
const Roles = require('./CompanyRoleAuthority');
const { requireDirectoryPermissions } = require('./DirectoryAuthority');
const { requireOuReceiver } = require('./AuthorityTenant');

// Source producer only. Public retirement and SQL fence receivers are not enabled yet.
class DeviceOuRetirementAuthority {
  constructor(database, { issuer = process.env.OIDC_ISSUER || 'http://localhost:3001', revalidate = createTenantStateClient() } = {}) {
    this.database = database; this.issuer = issuer; this.revalidate = revalidate;
  }
  read(body, user, authorization) { return this.resolve(body, user, authorization, true); }
  check(body, user, authorization) { return this.resolve(body, user, authorization, false); }
  async resolve(body, user, authorization, initial) {
    body = structuredClone(C.input(body));
    if (!this.database.isAvailable()) fail(503, 'Canonical retirement authority unavailable');
    if (user?.actor_type !== 'user' || user.iss !== this.issuer || typeof authorization !== 'string' || authorization.length > 16384 || !/^Bearer [A-Za-z0-9._~-]+$/.test(authorization)) fail(401, 'Original retirement human required');
    const tenant = await this.revalidate(authorization, user);
    const result = await this.database.transaction(async client => {
      // Cancellation must observe a preceding delete AFTER its OU lock is released.
      // Use a writing/read-committed transaction: a pre-lock repeatable snapshot is stale.
      await client.query('SET TRANSACTION ISOLATION LEVEL READ COMMITTED');
      await requireOuReceiver(client);
      await Roles.receiving(client);
      let actor = await Roles.actorProof(client, user);
      if (!sameTenantContext(tenant, actor.tenant)) fail(401, 'Original retirement tenant changed');
      if (initial && body.action === 'cancel') {
        await client.query('SELECT identity_directory_ou_lock($1::uuid)', [tenant.id]);
        actor = await Roles.actorProof(client, user);
      }
      const capture = async () => {
        const current = await new AuthorizationState({ transaction: callback => callback(client) }).state(user.iss, user.sub);
        if (!current.active || !sameContext(current.context, user.identity_authorization) || !sameTenantContext(current.tenant, tenant) || !acceptsRoleAuthentication(current.authentication, user)) fail(401, 'Original retirement actor changed');
        const unit = (await client.query("SELECT unit.id,unit.revision::text,ownership.generation::text FROM ous unit JOIN identity_tenant_ownership ownership ON ownership.resource_kind='ou' AND ownership.resource_id=unit.id AND ownership.tenant_id=$2 WHERE unit.id=$1 AND identity_tenant_id('ou',unit.id)=$2", [body.ouId, tenant.id])).rows[0];
        if (!unit) fail(404, 'Own retirement OU not found');
        if (unit.generation !== body.generation || unit.revision !== body.revision) fail(412, 'Original retirement OU changed');
        const canonical = { ...user, roles: current.roles };
        const captured = await requireDirectoryPermissions(client, canonical, ['ous.delete'], { kind: 'ou', id: body.ouId });
        const governance = await Roles.governance(client, canonical, 'ou', body.ouId);
        return { unit, captured: captured || null, governance: governance || null };
      };
      const original = await capture();
      const validUntil = Math.min(actor.validUntil, Roles.deadline(user, original.captured), original.governance?.validUntil || user.exp);
      const source = { schemaVersion: 1, deviceOuRetirementProtocol: 1, issuer: user.iss, subject: user.sub, tokenId: user.jti, expiresAt: user.exp,
        context: structuredClone(user.identity_authorization), tenant: actor.tenant, actorUserId: user.identity_authorization.userId, permissions: ['ous.delete'], validUntil,
        action: body.action, target: original.unit, fenceRevision: body.fenceRevision, protected: original.governance !== null,
        delegation: original.captured ? { grants: original.captured.grants.map(({ permission, source }) => ({ permission, source })) } : null };
      if (!isDeepStrictEqual(original, await capture()) || !C.validSource(source, user, body)) fail(401, 'Original retirement source changed');
      return source;
    });
    if (!sameTenantContext(tenant, await this.revalidate(authorization, user)) || !C.validSource(result, user, body)) fail(401, 'Original retirement authority expired');
    return result;
  }
}
module.exports = { DeviceOuRetirementAuthority };
