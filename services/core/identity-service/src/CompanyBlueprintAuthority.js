'use strict';

const { validContext, sameContext } = require('../../../../packages/identity-authorization-contract');
const { sameTenantContext } = require('../../../../packages/tenant-authorization-contract');
const { acceptsRoleAuthentication } = require('../../../../packages/role-authentication-contract');
const { createTenantStateClient } = require('../../../../packages/oidc-tenant-state');
const { COMPANY_BLUEPRINT_PERMISSIONS } = require('../../../../packages/company-blueprint-contract');
const { AuthorizationState } = require('./AuthorizationState');
const { companyOwner } = require('./CompanyOwner');

function fail(status, message) { throw Object.assign(new Error(message), { status }); }
class CompanyBlueprintAuthority {
  constructor(database, { issuer = process.env.OIDC_ISSUER || 'http://localhost:3001', revalidate = createTenantStateClient() } = {}) {
    this.database = database; this.issuer = issuer; this.revalidate = revalidate;
  }
  async read(user, authorization) {
    try {
      if (!this.database.isAvailable()) fail(503, 'Canonical company blueprint storage required');
      if (user?.actor_type !== 'user' || user.iss !== this.issuer || !validContext(user.identity_authorization)) fail(403, 'Canonical company blueprint human required');
      if (typeof authorization !== 'string' || authorization.length > 16384 || !/^Bearer [A-Za-z0-9._~-]+$/.test(authorization)) fail(401, 'Original company blueprint bearer required');
      if (!acceptsRoleAuthentication({ required: true, maxAgeSeconds: 300 }, user)) fail(428, 'Fresh company blueprint MFA required');
      const tenant = await this.revalidate(authorization, user);
      const result = await this.database.transaction(async client => {
        const source = await new AuthorizationState({ transaction: operation => operation(client) }).state(user.iss, user.sub);
        if (!source.active || !sameContext(source.context, user.identity_authorization) || !sameTenantContext(source.tenant, tenant) || !acceptsRoleAuthentication(source.authentication, user)) fail(401, 'Original company blueprint authority changed');
        const owner = source.roles.includes('admin') ? null : await companyOwner(client, user);
        if (!source.roles.includes('admin') && owner?.tenant_id !== tenant.id) fail(403, 'Actual own-company blueprint authority required');
        return { schemaVersion: 1, companyBlueprintProtocol: 1, issuer: user.iss, subject: user.sub, tokenId: user.jti, expiresAt: user.exp,
          context: source.context, tenant, actorUserId: source.context.userId, permissions: [...COMPANY_BLUEPRINT_PERMISSIONS],
          validUntil: Math.min(user.exp, user.auth_time + Math.min(300, source.authentication.required ? source.authentication.maxAgeSeconds : 300), Math.floor(Date.now() / 1000) + 300) };
      }, { readOnly: true });
      if (!sameTenantContext(tenant, await this.revalidate(authorization, user)) || !acceptsRoleAuthentication({ required: true, maxAgeSeconds: 300 }, user)
        || result.validUntil * 1000 <= Date.now()) fail(401, 'Original company blueprint authority changed');
      return result;
    } catch (error) {
      if (error.status) throw error;
      throw Object.assign(new Error('Canonical company blueprint authority unavailable'), { status: 503, cause: error });
    }
  }
}
module.exports = { CompanyBlueprintAuthority };
