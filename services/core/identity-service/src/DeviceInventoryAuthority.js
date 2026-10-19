'use strict';

const { validContext, sameContext, validUuid } = require('../../../../packages/identity-authorization-contract');
const { sameTenantContext } = require('../../../../packages/tenant-authorization-contract');
const { acceptsRoleAuthentication } = require('../../../../packages/role-authentication-contract');
const { createTenantStateClient } = require('../../../../packages/oidc-tenant-state');
const { AuthorizationState } = require('./AuthorizationState');
const { companyOwner } = require('./CompanyOwner');
const { INVENTORY_PERMISSIONS } = require('../../../../packages/device-inventory-contract');

function fail(status, message) { throw Object.assign(new Error(message), { status }); }
class DeviceInventoryAuthority {
  constructor(database, { issuer = process.env.OIDC_ISSUER || 'http://localhost:3001', revalidate = createTenantStateClient() } = {}) {
    this.database = database; this.issuer = issuer; this.revalidate = revalidate;
  }
  async read(user, authorization, body = null) {
    if (body !== null && (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).length !== 1 || !validUuid(body.userId))) fail(400, 'Exact canonical userId required');
    if (!this.database.isAvailable()) fail(503, 'Canonical identity storage required');
    if (user?.actor_type !== 'user' || user.iss !== this.issuer || !validContext(user.identity_authorization)) fail(403, 'Canonical inventory human required');
    if (!acceptsRoleAuthentication({ required: true, maxAgeSeconds: 300 }, user)) fail(428, 'Fresh inventory MFA required');
    const tenant = await this.revalidate(authorization, user);
    const result = await this.database.transaction(async client => {
      const source = await new AuthorizationState({ transaction: callback => callback(client) }).state(user.iss, user.sub);
      if (!source.active || !sameContext(source.context, user.identity_authorization) || !sameTenantContext(source.tenant, tenant) || !acceptsRoleAuthentication(source.authentication, user)) fail(401, 'Original inventory authority changed');
      const administrative = source.roles.includes('admin');
      const owner = administrative ? null : await companyOwner(client, user);
      if (!administrative && !owner) fail(403, 'Actual own-company inventory authority required');
      let target = null;
      if (body !== null) {
        const account = (await client.query("SELECT id,authorization_revision,enabled FROM users WHERE id=$1 AND identity_tenant_id('user',id)=$2", [body.userId.toLowerCase(), tenant.id])).rows[0];
        if (!account) fail(404, 'Own inventory recipient not found');
        target = { id: account.id, revision: String(account.authorization_revision), enabled: account.enabled };
      }
      return { schemaVersion: 1, issuer: user.iss, subject: user.sub, tokenId: user.jti, expiresAt: user.exp,
        context: source.context, tenant, actorUserId: source.context.userId, permissions: [...INVENTORY_PERMISSIONS],
        validUntil: Math.min(user.exp, user.auth_time + Math.min(300, source.authentication.required ? source.authentication.maxAgeSeconds : 300)), target };
    }, { readOnly: true });
    if (!sameTenantContext(tenant, await this.revalidate(authorization, user)) || !acceptsRoleAuthentication({ required: true, maxAgeSeconds: 300 }, user)
      || result.validUntil * 1000 <= Date.now()) fail(401, 'Original inventory authority changed');
    return result;
  }
}
module.exports = { DeviceInventoryAuthority };
