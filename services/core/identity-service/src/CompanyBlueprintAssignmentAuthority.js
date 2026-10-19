'use strict';

const { validContext, sameContext } = require('../../../../packages/identity-authorization-contract');
const { sameTenantContext } = require('../../../../packages/tenant-authorization-contract');
const { acceptsRoleAuthentication } = require('../../../../packages/role-authentication-contract');
const { createTenantStateClient } = require('../../../../packages/oidc-tenant-state');
const { COMPANY_BLUEPRINT_ASSIGNMENT_PERMISSIONS, exact, identifier, validSource } = require('../../../../packages/company-blueprint-assignment-contract');
const { AuthorizationState } = require('./AuthorizationState');
const { companyOwner } = require('./CompanyOwner');

function fail(status, message) { throw Object.assign(new Error(message), { status }); }
class CompanyBlueprintAssignmentAuthority {
  constructor(database, { issuer = process.env.OIDC_ISSUER || 'http://localhost:3001', revalidate = createTenantStateClient() } = {}) {
    this.database = database; this.issuer = issuer; this.revalidate = revalidate;
  }
  async read(user, authorization, body = null) {
    if (body !== null) { exact(body, ['userId']); identifier(body.userId); }
    try {
      if (!this.database.isAvailable()) fail(503, 'Canonical company blueprint assignment storage required');
      if (user?.actor_type !== 'user' || user.token_use !== 'access' || user.iss !== this.issuer || !validContext(user.identity_authorization)
        || typeof user.jti !== 'string' || !user.jti || !Number.isSafeInteger(user.exp)) fail(403, 'Canonical company blueprint assignment human required');
      if (typeof authorization !== 'string' || authorization.length > 16384 || !/^Bearer [A-Za-z0-9._~-]+$/.test(authorization)) fail(401, 'Original company blueprint assignment bearer required');
      if (!acceptsRoleAuthentication({ required: true, maxAgeSeconds: 300 }, user)) fail(428, 'Fresh company blueprint assignment MFA required');
      const tenant = await this.revalidate(authorization, user);
      const result = await this.database.transaction(async client => {
        const source = await new AuthorizationState({ transaction: operation => operation(client) }).state(user.iss, user.sub);
        if (!source.active || !sameContext(source.context, user.identity_authorization) || !sameTenantContext(source.tenant, tenant) || !acceptsRoleAuthentication(source.authentication, user)) fail(401, 'Original company blueprint assignment authority changed');
        const owner = source.roles.includes('admin') ? null : await companyOwner(client, user);
        if (!source.roles.includes('admin') && owner?.tenant_id !== tenant.id) fail(403, 'Actual own-company blueprint assignment authority required');
        let target = null;
        if (body !== null) {
          const home = (await client.query("SELECT identity_tenant_id('user',$1::uuid) AS tenant_id", [body.userId])).rows[0]?.tenant_id;
          if (home !== tenant.id) fail(404, 'Own company blueprint assignment recipient not found');
          const account = (await client.query('SELECT id,authorization_revision,eligibility_revision,identity_tenant_user_enabled(id) AS enabled FROM users WHERE id=$1', [body.userId])).rows[0];
          if (account) target = { id: account.id, revision: String(account.authorization_revision), eligibilityRevision: String(account.eligibility_revision), enabled: account.enabled, deleted: false };
          else {
            const deleted = (await client.query('SELECT revision FROM identity_deleted_users WHERE user_id=$1', [body.userId])).rows[0];
            if (!deleted) fail(404, 'Own company blueprint assignment recipient not found');
            target = { id: body.userId, revision: null, eligibilityRevision: String(deleted.revision), enabled: false, deleted: true };
          }
        }
        return { schemaVersion: 1, companyBlueprintAssignmentsProtocol: 1, issuer: user.iss, subject: user.sub, tokenId: user.jti, expiresAt: user.exp,
          context: source.context, tenant, actorUserId: source.context.userId, permissions: [...COMPANY_BLUEPRINT_ASSIGNMENT_PERMISSIONS],
          validUntil: Math.min(user.exp, user.auth_time + Math.min(300, source.authentication.required ? source.authentication.maxAgeSeconds : 300), Math.floor(Date.now() / 1000) + 300), target };
      }, { readOnly: true });
      if (!sameTenantContext(tenant, await this.revalidate(authorization, user)) || !validSource(result, user, body?.userId ?? null)) fail(401, 'Original company blueprint assignment authority changed');
      return result;
    } catch (error) {
      if (error.status) throw error;
      throw Object.assign(new Error('Canonical company blueprint assignment authority unavailable'), { status: 503, cause: error });
    }
  }
}
module.exports = { CompanyBlueprintAssignmentAuthority };
