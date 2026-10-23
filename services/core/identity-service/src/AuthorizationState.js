'use strict';

const { createRemoteJWKSet, jwtVerify } = require('jose');
const { readRoleState } = require('./RoleState');
const { PATH, TARGET_PATH, TARGET_PURPOSE, COMPANY_CONSOLE_PATH, COMPANY_CONSOLE_PURPOSE, AUDIENCE, PURPOSE, TYPE, validUuid, validMemberships } = require('../../../../packages/identity-authorization-contract');
const { ownerState } = require('./CompanyOwner');
const { createHash } = require('node:crypto');
const { validTenantContext } = require('../../../../packages/tenant-authorization-contract');

function authorizationRequest({ issuer = process.env.OIDC_ISSUER || 'http://localhost:3001', jwksUri = process.env.JWKS_URI || 'http://localhost:3001/jwks', target = false, companyConsole = false } = {}) {
  let jwks;
  const path = companyConsole ? COMPANY_CONSOLE_PATH : target ? TARGET_PATH : PATH; const purpose = companyConsole ? COMPANY_CONSOLE_PURPOSE : target ? TARGET_PURPOSE : PURPOSE;
  const scope = companyConsole ? 'identity.company-console.read' : target ? 'identity.application-target.read' : 'identity.authorization.read';
  return async (req, res, next) => {
    res.set('Cache-Control', 'no-store');
    const validBody = companyConsole ? req.body && Object.keys(req.body).length === 2 && validUuid(req.body.userId) && typeof req.body.clientId === 'string' && /^[A-Za-z0-9._~-]{1,255}$/.test(req.body.clientId)
      : target ? req.body && Object.keys(req.body).length === 3 && ['user','group'].includes(req.body.targetType)
      && validUuid(req.body.targetId) && validUuid(req.body.actorUserId)
      : typeof req.body?.subject === 'string' && !!req.body.subject.trim() && req.body.subject.length <= 255 && Object.keys(req.body).length === 1;
    if (req.method !== 'POST' || req.originalUrl !== path || !validBody || req.headers['x-api-key']
      || typeof req.headers.authorization !== 'string' || req.headers.authorization.length > 8192 || !/^Bearer [A-Za-z0-9._~-]+$/.test(req.headers.authorization)) return res.status(401).json({ error: 'invalid_authority_request' });
    try {
      if (!jwks) jwks = createRemoteJWKSet(new URL(jwksUri), { timeoutDuration: 1500, cooldownDuration: 1000, cacheMaxAge: 30000 });
      const { payload, protectedHeader } = await jwtVerify(req.headers.authorization.slice(7), jwks, { issuer, audience: AUDIENCE,
        algorithms: ['RS256'], requiredClaims: ['sub', 'jti', 'exp', 'iat'] });
      const now = Math.floor(Date.now() / 1000);
      if (Object.keys(protectedHeader).some(field => !['alg', 'kid', 'typ'].includes(field)) || protectedHeader.typ !== TYPE
        || typeof protectedHeader.kid !== 'string' || !protectedHeader.kid || protectedHeader.kid.length > 128
        || payload.aud !== AUDIENCE || payload.sub !== 'oauth-provider' || payload.actor_type !== 'workload' || payload.token_use !== purpose
        || payload.scope !== scope || payload.htm !== 'POST' || payload.htu !== path
        || (companyConsole ? payload.console_client_id !== req.body.clientId || payload.console_user_id !== req.body.userId : target ? payload.target_type !== req.body.targetType || payload.target_id !== req.body.targetId || payload.actor_user_id !== req.body.actorUserId : payload.request_subject !== req.body.subject)
        || !Number.isInteger(payload.iat) || payload.iat > now + 5 || !Number.isInteger(payload.exp) || payload.exp <= payload.iat || payload.exp - payload.iat > 30
        || typeof payload.jti !== 'string' || payload.jti.length !== 36 || !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(payload.jti)) return res.status(401).json({ error: 'invalid_authority_request' });
      req.authorityIssuer = payload.iss;
      next();
    } catch (error) {
      const unavailable = ['ERR_JWKS_TIMEOUT', 'ERR_JWKS_INVALID', 'ECONNREFUSED', 'ENOTFOUND', 'EAI_AGAIN'].includes(error.code)
        || error instanceof TypeError || /Expected 200 OK/.test(error.message);
      return res.status(unavailable ? 503 : 401).json({ error: unavailable ? 'authority_verification_unavailable' : 'invalid_authority_request' });
    }
  };
}

class AuthorizationState {
  constructor(database) { this.database = database; }
  async companyConsole(issuer, clientId, userId) {
    return this.database.transaction(async client => {
      const owner = await ownerState(client, userId); const active = !!owner?.active && owner.issuer === issuer && owner.console_client_id === clientId;
      return { schemaVersion: 1, clientId, userId, active, revision: active ? createHash('sha256').update(JSON.stringify(['company-console-owner-v1', clientId, userId, owner.id, owner.tenant_id])).digest('hex') : null };
    }, { readOnly: true });
  }

  async state(issuer, subject) {
    return this.database.transaction(async client => {
      await client.query("SET LOCAL statement_timeout = '1000ms'");
      const result = await client.query(`SELECT users.id,identity_tenant_user_enabled(users.id) AS enabled,users.authorization_revision AS revision,
        identity_subject_links.authorization_revision AS link_revision,tenant.id AS tenant_id,tenant.version AS tenant_version,tenant.generation AS tenant_generation FROM identity_subject_links
        JOIN users ON users.id=identity_subject_links.user_id
        JOIN identity_tenants tenant ON tenant.id=identity_tenant_id('user',users.id)
        JOIN identity_subject_tenant_bindings binding ON binding.issuer=identity_subject_links.issuer AND binding.subject=identity_subject_links.subject
          AND binding.tenant_id=tenant.id WHERE identity_subject_links.issuer=$1 AND identity_subject_links.subject=$2`, [issuer, subject]);
      const row = result.rows[0];
      if (!row || row.enabled !== true) return { schemaVersion: 1, issuer, subject, active: false };
      await client.query('SELECT identity_company_group_rule_live_receiving()');
      const { roles, rolesRevision, authentication } = await readRoleState(client, row.id);
      const memberships = (await client.query(`SELECT group_members.group_id,group_members.membership_id FROM group_members
        JOIN groups ON groups.id=group_members.group_id WHERE group_members.user_id=$1 AND identity_membership_review_allowed(group_members.membership_id)
        AND identity_tenant_id('group',groups.id)=identity_tenant_id('user',$1::uuid) ORDER BY group_members.group_id LIMIT 257`, [row.id])).rows
        .map(member => ({ groupId: member.group_id, membershipId: member.membership_id }));
      if (!validMemberships(memberships)) throw new Error('Invalid canonical membership state');
      const tenant = { id: row.tenant_id, version: String(row.tenant_version), generation: String(row.tenant_generation) };
      if (!validTenantContext(tenant)) throw new Error('Invalid canonical tenant state');
      return { schemaVersion: 6, issuer, subject, active: true, roles, memberships, authentication, tenant,
        context: { userId: row.id, revision: String(row.revision), linkRevision: String(row.link_revision), rolesRevision } };
    }, { readOnly: true });
  }

  async target(targetType, targetId, actorUserId) {
    if (!['user','group'].includes(targetType) || !validUuid(targetId) || !validUuid(actorUserId)) throw new Error('Invalid application target');
    return this.database.transaction(async client => {
      await client.query("SET LOCAL statement_timeout = '1000ms'");
      const result = targetType === 'user'
        ? await client.query("SELECT id,identity_tenant_user_enabled(id) AS enabled,eligibility_revision AS revision FROM users WHERE id=$1 AND identity_tenant_user_enabled($2::uuid) AND identity_tenant_id('user',id)=identity_tenant_id('user',$2::uuid)", [targetId,actorUserId])
        : await client.query(`SELECT id,revision,EXISTS(SELECT 1 FROM group_members WHERE group_id=groups.id AND user_id=$2) AS actor_member FROM groups WHERE id=$1
          AND identity_tenant_user_enabled($2::uuid) AND identity_tenant_id('group',id)=identity_tenant_id('user',$2::uuid)`, [targetId, actorUserId]);
      const row = result.rows[0]; const active = !!row && (targetType === 'group' || row.enabled === true);
      return { schemaVersion: 1, targetType, targetId, active, revision: active ? String(row.revision) : null,
        actorIsMember: active && (targetType === 'user' ? targetId.toLowerCase() === actorUserId.toLowerCase() : row.actor_member === true) };
    }, { readOnly: true });
  }

  async invalidate(userId, actor) {
    if (typeof userId !== 'string' || userId.length !== 36 || !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(userId)) throw Object.assign(new Error('Invalid user identifier'), { status: 400 });
    const result = await this.database.write('UPDATE users SET authorization_revision=authorization_revision+1 WHERE id=$1 RETURNING authorization_revision', [userId], actor);
    if (!result.rows[0]) throw Object.assign(new Error('User not found'), { status: 404 });
    return { userId, revision: String(result.rows[0].authorization_revision) };
  }
}

module.exports = { AuthorizationState, authorizationRequest, authorizationTargetRequest: options => authorizationRequest({ ...options, target: true }), readRoleState };
