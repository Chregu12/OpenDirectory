'use strict';

const { validContext, sameContext, validUuid } = require('../../../../packages/identity-authorization-contract');
const { sameTenantContext } = require('../../../../packages/tenant-authorization-contract');
const { acceptsRoleAuthentication } = require('../../../../packages/role-authentication-contract');
const { createTenantStateClient } = require('../../../../packages/oidc-tenant-state');
const { AuthorizationState } = require('./AuthorizationState');
const { companyOwner } = require('./CompanyOwner');
const { INVENTORY_PERMISSIONS } = require('../../../../packages/device-inventory-contract');
const COMPLIANCE = require('../../../../packages/device-compliance-contract');
const CompanyRoles = require('./CompanyRoleAuthority');
const { validDelegation } = require('../../../../packages/device-delegation-contract');
const Scope = require('../../../../packages/device-scope-contract');
const DeviceScopes = require('./DeviceScopeAuthority');

function fail(status, message) { throw Object.assign(new Error(message), { status }); }
class DeviceInventoryAuthority {
  constructor(database, { issuer = process.env.OIDC_ISSUER || 'http://localhost:3001', revalidate = createTenantStateClient() } = {}) {
    this.database = database; this.issuer = issuer; this.revalidate = revalidate;
  }
  async readScoped(user, authorization, body = null, compliance = false) {
    let selected = null;
    if (body !== null && Object.hasOwn(body,'device')) {
      if (!Scope.exact(body,['userId','device']) || body.userId !== null && !validUuid(body.userId) || !Scope.resource(body.device)) fail(400,'Exact device scope resource required');
      selected = structuredClone(body.device); body = body.userId === null ? null : { userId:body.userId };
    }
    return this.read(user,authorization,body,compliance,true,selected);
  }
  async read(user, authorization, body = null, compliance = false, scoped = false, selected = null) {
    if (compliance && body !== null) fail(400, 'No compliance target overrides');
    if (body !== null && (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).length !== 1 || !validUuid(body.userId))) fail(400, 'Exact canonical userId required');
    if (!this.database.isAvailable()) fail(503, 'Canonical identity storage required');
    if (user?.actor_type !== 'user' || user.iss !== this.issuer || !validContext(user.identity_authorization)) fail(403, 'Canonical inventory human required');
    if (!acceptsRoleAuthentication({ required: true, maxAgeSeconds: 300 }, user)) fail(428, 'Fresh inventory MFA required');
    const tenant = await this.revalidate(authorization, user);
    const snapshot = () => this.database.transaction(async client => {
      const source = await new AuthorizationState({ transaction: callback => callback(client) }).state(user.iss, user.sub);
      if (!source.active || !sameContext(source.context, user.identity_authorization) || !sameTenantContext(source.tenant, tenant) || !acceptsRoleAuthentication(source.authentication, user)) fail(401, 'Original inventory authority changed');
      const administrative = source.roles.includes('admin') || source.roles.includes('device-enrollment-operator') || compliance && (source.roles.includes('policy-administrator') || source.roles.includes('compliance-reader'));
      const manager = source.roles.includes('admin') || compliance && source.roles.includes('policy-administrator');
      const owner = compliance ? (manager ? null : await companyOwner(client, user)) : administrative ? null : await companyOwner(client, user);
      const available=compliance?COMPLIANCE.PERMISSIONS:INVENTORY_PERMISSIONS;
      const inherent=administrative||owner?(compliance?COMPLIANCE.PERMISSIONS.slice(0,manager||owner?2:1):[...INVENTORY_PERMISSIONS]):[];
      const captured = scoped && inherent.length !== available.length ? await DeviceScopes.capture(client,user,available,tenant.id,inherent) : null;
      const limited = captured?.grants.some(grant => grant.source.scopeType === 'device-ou') === true;
      const grants=limited?captured.grants:inherent.length===available.length?[]:await CompanyRoles.tenantGrants(client,user,available);
      const permissions=available.filter(permission=>inherent.includes(permission)||grants.some(grant=>grant.permission===permission));
      if(!permissions.length||compliance&&!COMPLIANCE.permissions(permissions))fail(403,'Actual own-company inventory authority required');
      let target = null;
      if (body !== null) {
        const account = (await client.query("SELECT id,authorization_revision,enabled FROM users WHERE id=$1 AND identity_tenant_id('user',id)=$2", [body.userId.toLowerCase(), tenant.id])).rows[0];
        if (!account) fail(404, 'Own inventory recipient not found');
        target = { id: account.id, revision: String(account.authorization_revision), enabled: account.enabled };
      }
      const result={ schemaVersion: limited ? 2 : 1, issuer: user.iss, subject: user.sub, tokenId: user.jti, expiresAt: user.exp,
        context: source.context, tenant, actorUserId: source.context.userId, permissions,
        validUntil: Math.min(user.exp, user.auth_time + Math.min(300, source.authentication.required ? source.authentication.maxAgeSeconds : 300),...grants.map(grant=>Number(grant.source.validUntil))), target,
        ...(limited?{scope:{protocol:1,inherent,grants,units:captured.units,resource:selected}}:grants.length?{delegation:{grants}}:{}) };
      if(limited && result.validUntil*1000 <= Date.now())fail(401,'Original device scope expired');
      if(limited?!Scope.validEnvelope(result,user,body?.userId || null,compliance,selected):grants.length&&!validDelegation(result,user))fail(503,'Original device delegation unavailable');
      return result;
    }, { readOnly: true });
    const result = await snapshot();
    if (!sameTenantContext(tenant, await this.revalidate(authorization, user)) || !acceptsRoleAuthentication({ required: true, maxAgeSeconds: 300 }, user)
      || result.validUntil * 1000 <= Date.now()) fail(401, 'Original inventory authority changed');
    if(result.delegation){const current=await this.database.transaction(client=>CompanyRoles.tenantGrants(client,user,compliance?COMPLIANCE.PERMISSIONS:INVENTORY_PERMISSIONS),{readOnly:true});if(JSON.stringify(current)!==JSON.stringify(result.delegation.grants))fail(401,'Original device delegation changed');}
    if(result.scope){
      let current;
      try{current=await snapshot();}catch(error){if([401,403,404,428].includes(error.status))fail(401,'Original device scope changed');throw error;}
      if(JSON.stringify(result)!==JSON.stringify(current) || !Scope.validEnvelope(result,user,body?.userId || null,compliance,selected))fail(401,'Original device scope changed');
    }
    return result;
  }
}
module.exports = { DeviceInventoryAuthority };
