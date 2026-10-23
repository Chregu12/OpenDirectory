'use strict';

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { PATH, TARGET_PATH, TARGET_PURPOSE, COMPANY_CONSOLE_PATH, COMPANY_CONSOLE_PURPOSE, AUDIENCE, PURPOSE, TYPE, validContext, sameContext, validMemberships, validUuid, validRevision } = require('../../../../packages/identity-authorization-contract');
const { validRoles, rolePermissions } = require('../../../../packages/directory-role-contract');
const { validAuthentication, acceptsRoleAuthentication } = require('../../../../packages/role-authentication-contract');
const { validTenantContext } = require('../../../../packages/tenant-authorization-contract');

class IdentityAuthorityError extends Error {
  constructor(status, code) { super(code); this.status = status; this.code = code; }
}

class IdentityAuthority {
  constructor({ signingKeys, issuer, endpoint = process.env.OAUTH_IDENTITY_AUTHORITY_URL || 'http://identity-service:3001' + PATH,
    demo = false, production = process.env.NODE_ENV === 'production', fetchImpl = (...args) => global.fetch(...args) }) {
    if (demo && production) throw new Error('Identity authority bypass is forbidden in production');
    const url = new URL(endpoint);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.hash || url.search || url.pathname !== PATH) throw new Error('Invalid identity authority URL');
    this.url = url; this.issuer = issuer; this.keys = signingKeys; this.demo = demo; this.fetch = fetchImpl;
  }

  async request(path, purpose, scope, body, claims) {
    const assertion = jwt.sign({ iss: this.issuer, sub: 'oauth-provider', aud: AUDIENCE, actor_type: 'workload',
      scope, token_use: purpose, ...claims, htm: 'POST', htu: path, jti: crypto.randomUUID() }, this.keys.privateKey,
    { algorithm: 'RS256', keyid: this.keys.kid, header: { typ: TYPE }, expiresIn: 30 });
    const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 1500);
    try {
      const response = await this.fetch(new URL(path, this.url), { method: 'POST', headers: { Authorization: 'Bearer ' + assertion, 'Content-Type': 'application/json' },
        body: JSON.stringify(body), redirect: 'error', cache: 'no-store', signal: controller.signal });
      if (response.status !== 200 || !response.headers.get('content-type')?.includes('application/json')) throw new Error('Authority unavailable');
      const chunks = []; let length = 0;
      for await (const chunk of response.body) {
        length += chunk.length; if (length > 65536) throw new Error('Oversized authority response'); chunks.push(Buffer.from(chunk));
      }
      return JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } catch (error) {
      if (error instanceof IdentityAuthorityError) throw error;
      throw new IdentityAuthorityError(503, 'identity_authority_unavailable');
    } finally { clearTimeout(timer); controller.abort(); }
  }

  async state(subject) {
    if (this.demo) return { context: undefined, memberships: [] };
    if (typeof subject !== 'string' || !subject.trim() || subject.length > 255) throw new IdentityAuthorityError(403, 'identity_not_eligible');
    const state = await this.request(PATH, PURPOSE, 'identity.authorization.read', { subject }, { request_subject: subject });
    if (![1,6].includes(state?.schemaVersion) || state.issuer !== this.issuer || state.subject !== subject || typeof state.active !== 'boolean'
      || (state.active && (state.schemaVersion !== 6 || !validTenantContext(state.tenant) || !validContext(state.context) || !validRoles(state.roles) || !validMemberships(state.memberships) || !validAuthentication(state.authentication)))) throw new IdentityAuthorityError(503, 'identity_authority_unavailable');
    if (!state.active) throw new IdentityAuthorityError(403, 'identity_not_eligible');
    return { context: state.context, tenant: state.tenant, authorization: { roles: state.roles, permissions: rolePermissions(state.roles) }, memberships: state.memberships, authentication: state.authentication };
  }

  async target(targetType, targetId, actorUserId) {
    if (!['user','group'].includes(targetType) || !validUuid(targetId) || !validUuid(actorUserId)) throw new IdentityAuthorityError(400, 'invalid_application_target');
    const body = { targetType, targetId, actorUserId };
    const state = await this.request(TARGET_PATH, TARGET_PURPOSE, 'identity.application-target.read', body,
      { target_type: targetType, target_id: targetId, actor_user_id: actorUserId });
    if (state?.schemaVersion !== 1 || state.targetType !== targetType || state.targetId !== targetId || typeof state.active !== 'boolean'
      || typeof state.actorIsMember !== 'boolean' || (state.active ? !validRevision(state.revision) : state.revision !== null)) throw new IdentityAuthorityError(503, 'identity_authority_unavailable');
    if (!state.active) throw new IdentityAuthorityError(403, 'application_target_ineligible');
    return state;
  }

  async context(subject) { return (await this.state(subject)).context; }
  async companyAppTenant(clientId,tenant){
    const contract=require('../../../../packages/company-app-contract');
    if(this.demo||!validTenantContext(tenant))throw new IdentityAuthorityError(503,'company_app_tenant_authority_unavailable');
    const value=await this.request(contract.TENANT_PATH,contract.TENANT_PURPOSE,'identity.company-app-tenant.read',{clientId,tenant},{app_client_id:clientId,app_tenant:tenant});
    if(!value||Object.keys(value).length!==5||value.schemaVersion!==1||value.companyAppProtocol!==1||value.clientId!==clientId||!require('../../../../packages/tenant-authorization-contract').sameTenantContext(value.tenant,tenant)||typeof value.active!=='boolean')throw new IdentityAuthorityError(503,'company_app_tenant_authority_unavailable');return value.active;
  }
  async companyConsole(clientId, userId) {
    if (!validUuid(userId) || typeof clientId !== 'string' || !/^[A-Za-z0-9._~-]{1,255}$/.test(clientId)) throw new IdentityAuthorityError(400, 'invalid_company_console_target');
    const value = await this.request(COMPANY_CONSOLE_PATH, COMPANY_CONSOLE_PURPOSE, 'identity.company-console.read', { clientId, userId }, { console_client_id: clientId, console_user_id: userId });
    if (value?.schemaVersion !== 1 || Object.keys(value).length !== 5 || value.clientId !== clientId || value.userId !== userId || typeof value.active !== 'boolean'
      || (value.active ? typeof value.revision !== 'string' || !/^[a-f0-9]{64}$/.test(value.revision) : value.revision !== null)) throw new IdentityAuthorityError(503, 'company_console_authority_unavailable'); return value;
  }

  async verifiedState(payload) {
    if (this.demo || payload.actor_type === 'application') return { demo: this.demo, memberships: [] };
    if (payload.actor_type !== 'user' || payload.iss !== this.issuer || !validContext(payload.identity_authorization)) return false;
    try {
      const state = await this.state(payload.sub);
      if (!sameContext(state.context, payload.identity_authorization) || !acceptsRoleAuthentication(state.authentication, payload)) return false;
      const expected = payload.scope?.split(' ').includes('roles') ? state.authorization : {};
      return ['roles', 'permissions'].every(claim => JSON.stringify(payload[claim]) === JSON.stringify(expected[claim])) ? state : false;
    }
    catch (error) { if (error.status === 403) return false; throw error; }
  }
  async active(payload) { return !!await this.verifiedState(payload); }
}

module.exports = { IdentityAuthority, IdentityAuthorityError };
