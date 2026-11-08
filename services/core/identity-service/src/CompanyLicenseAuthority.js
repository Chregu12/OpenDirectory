'use strict';

const { validContext, sameContext } = require('../../../../packages/identity-authorization-contract');
const { sameTenantContext } = require('../../../../packages/tenant-authorization-contract');
const { acceptsRoleAuthentication } = require('../../../../packages/role-authentication-contract');
const { createTenantStateClient } = require('../../../../packages/oidc-tenant-state');
const { COMPANY_LICENSE_PERMISSIONS, exact, identifier } = require('../../../../packages/company-license-contract');
const activationContract = require('../../../../packages/company-license-activation');
const defaultActivationState = require('./CompanyLicenseActivationClient');
const { isDeepStrictEqual } = require('util');
const { AuthorizationState } = require('./AuthorizationState');
const { companyOwner } = require('./CompanyOwner');
function fail(status, message) { throw Object.assign(new Error(message), { status }); }
class CompanyLicenseAuthority {
  constructor(database, { issuer = process.env.OIDC_ISSUER || 'http://localhost:3001', revalidate = createTenantStateClient(), activationState = defaultActivationState } = {}) {
    this.database = database; this.issuer = issuer; this.revalidate = revalidate; this.activationState = activationState;
  }
  async read(user, authorization, body = null, eligibility = false) {
    if (body !== null) { exact(body, ['userId']); identifier(body.userId); }
    if (!this.database.isAvailable()) fail(503, 'Canonical company license storage required');
    if (user?.actor_type !== 'user' || user.iss !== this.issuer || !validContext(user.identity_authorization)) fail(403, 'Canonical company license human required');
    const activation = eligibility ? null : await this.activationState(user, authorization);
    const active = !eligibility && activation.known && activationContract.validClaim(user.company_license_activation)
      && isDeepStrictEqual(activation.activation, user.company_license_activation) && activationContract.deadline(user) > Math.floor(Date.now() / 1000);
    if (!eligibility && (activation.known ? !active : !acceptsRoleAuthentication({ required: true, maxAgeSeconds: 300 }, user))) fail(428, 'Fresh company license MFA or active license window required');
    const tenant = await this.revalidate(authorization, user);
    const result = await this.database.transaction(async client => {
      const source = await new AuthorizationState({ transaction: operation => operation(client) }).state(user.iss, user.sub);
      if (!source.active || !sameContext(source.context, user.identity_authorization) || !sameTenantContext(source.tenant, tenant) || !acceptsRoleAuthentication(source.authentication, user)) fail(401, 'Original company license authority changed');
      if (!source.roles.includes('admin') && !await companyOwner(client, user)) fail(403, 'Actual own-company license authority required');
      let target = null;
      if (body !== null) {
        const owner = (await client.query("SELECT identity_tenant_id('user',$1::uuid) AS tenant_id", [body.userId])).rows[0]?.tenant_id;
        if (owner !== tenant.id) fail(404, 'Own company license recipient not found');
        const account = (await client.query('SELECT id,authorization_revision,eligibility_revision,identity_tenant_user_enabled(id) AS enabled FROM users WHERE id=$1', [body.userId])).rows[0];
        if (account) target = { id: account.id, revision: String(account.authorization_revision), eligibilityRevision: String(account.eligibility_revision), enabled: account.enabled, deleted: false };
        else {
          const deleted = (await client.query('SELECT revision FROM identity_deleted_users WHERE user_id=$1', [body.userId])).rows[0];
          if (!deleted) fail(404, 'Own company license recipient not found');
          target = { id: body.userId, revision: null, eligibilityRevision: String(deleted.revision), enabled: false, deleted: true };
        }
      }
      return { schemaVersion: 1, issuer: user.iss, subject: user.sub, tokenId: user.jti, expiresAt: user.exp, context: source.context, tenant,
        actorUserId: source.context.userId, permissions: [...COMPANY_LICENSE_PERMISSIONS], validUntil: Math.min(user.exp, eligibility ? user.exp : active ? activationContract.deadline(user) : user.auth_time + 300, source.authentication.required ? user.auth_time + source.authentication.maxAgeSeconds : user.exp), target };
    }, { readOnly: true });
    if (!sameTenantContext(tenant, await this.revalidate(authorization, user)) || (active && !sameTenantContext(tenant, activation.activation.tenant))
      || (!eligibility && !isDeepStrictEqual(activation, await this.activationState(user, authorization))) || result.validUntil * 1000 <= Date.now()) fail(401, 'Original company license authority changed');
    return result;
  }
}
module.exports = { CompanyLicenseAuthority };
