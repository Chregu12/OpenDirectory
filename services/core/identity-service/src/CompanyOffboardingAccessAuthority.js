'use strict';

const { validContext, sameContext } = require('../../../../packages/identity-authorization-contract');
const { sameTenantContext } = require('../../../../packages/tenant-authorization-contract');
const { acceptsRoleAuthentication } = require('../../../../packages/role-authentication-contract');
const { createTenantStateClient } = require('../../../../packages/oidc-tenant-state');
const { AuthorizationState } = require('./AuthorizationState');
const { getIdentityPermissions } = require('./middleware/identityAccess');
const PERMISSIONS = ['identities.roles.read', 'identities.roles.manage', 'pim.eligibilities.read', 'pim.eligibilities.manage'];
function fail(status, message) { throw Object.assign(new Error(message), { status }); }

class CompanyOffboardingAccessAuthority {
  constructor(database, { issuer = process.env.OIDC_ISSUER || 'http://localhost:3001', revalidate = createTenantStateClient() } = {}) {
    this.database = database; this.issuer = issuer; this.revalidate = revalidate;
  }
  async read(user, authorization) {
    if (!this.database.isAvailable()) fail(503, 'Canonical access cleanup storage required');
    if (user?.actor_type !== 'user' || user.iss !== this.issuer || !validContext(user.identity_authorization)
      || typeof user.jti !== 'string' || !user.jti || !Number.isSafeInteger(user.exp)
      || typeof authorization !== 'string' || authorization.length > 16384 || !/^Bearer [A-Za-z0-9._~-]+$/.test(authorization)) fail(403, 'Canonical access cleanup human required');
    if (!acceptsRoleAuthentication({ required: true, maxAgeSeconds: 300 }, user)) fail(428, 'Fresh access cleanup MFA required');
    const tenant = await this.revalidate(authorization, user);
    const result = await this.database.transaction(async client => {
      const source = await new AuthorizationState({ transaction: operation => operation(client) }).state(user.iss, user.sub);
      if (!source.active || !sameContext(source.context, user.identity_authorization) || !sameTenantContext(source.tenant, tenant)
        || !acceptsRoleAuthentication(source.authentication, user)) fail(401, 'Original access cleanup authority changed');
      const actual = getIdentityPermissions({ roles: source.roles });
      return { issuer: user.iss, subject: user.sub, tokenId: user.jti, expiresAt: user.exp, context: source.context, tenant,
        actorUserId: source.context.userId, roles: source.roles, permissions: PERMISSIONS.filter(permission => actual.includes(permission)),
        validUntil: Math.min(user.exp, user.auth_time + Math.min(300, source.authentication.required ? source.authentication.maxAgeSeconds : 300)) };
    }, { readOnly: true });
    if (!sameTenantContext(tenant, await this.revalidate(authorization, user)) || result.validUntil * 1000 <= Date.now()
      || !acceptsRoleAuthentication({ required: true, maxAgeSeconds: 300 }, user)) fail(401, 'Original access cleanup authority changed');
    return result;
  }
}
module.exports = { CompanyOffboardingAccessAuthority, PERMISSIONS };
