'use strict';

const { validUuid, validContext } = require('../../../../packages/identity-authorization-contract');
const { sameTenantContext } = require('../../../../packages/tenant-authorization-contract');
const { createTenantStateClient } = require('../../../../packages/oidc-tenant-state');
const { readRoleState } = require('./RoleState');
const { acceptsRoleAuthentication } = require('../../../../packages/role-authentication-contract');
const { getIdentityPermissions } = require('./middleware/identityAccess');

function reject(status, message) { throw Object.assign(new Error(message), { status }); }

class SubjectLinks {
  constructor(database, { issuer = process.env.OIDC_ISSUER || 'http://localhost:3001', revalidate = createTenantStateClient() } = {}) {
    this.database = database; this.issuer = issuer; this.revalidate = revalidate;
  }

  async mutate(body, user, authorization, deleting = false) {
    const keys = deleting ? ['issuer','subject'] : ['issuer','subject','userId'];
    if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).length !== keys.length
      || Object.keys(body).some(key => !keys.includes(key)) || body.issuer !== this.issuer
      || typeof body.subject !== 'string' || !body.subject.trim() || body.subject.length > 255 || /[\u0000-\u001f\u007f]/.test(body.subject)
      || !deleting && !validUuid(body.userId)) reject(400, 'Exact trusted subject-link fields required');
    if (user?.actor_type !== 'user' || user.iss !== this.issuer || !validContext(user.identity_authorization)
      || !getIdentityPermissions(user).includes('identities.links.manage')) reject(403, 'Canonical subject-link administrator required');
    if (deleting && body.issuer === user.iss && body.subject === user.sub) reject(403, 'Another operator must unlink this session identity');
    const tenant = await this.revalidate(authorization, user);
    return this.database.transaction(async client => {
      const current = (await client.query('SELECT id,version,generation FROM identity_tenants WHERE id=$1 AND enabled FOR SHARE', [tenant.id])).rows[0];
      if (!current || !sameTenantContext(tenant, { id: current.id, version: String(current.version), generation: String(current.generation) })) reject(401, 'Tenant authority changed');
      const actor = (await client.query(`SELECT account.authorization_revision,link.authorization_revision AS link_revision FROM users account
        JOIN identity_subject_links link ON link.user_id=account.id WHERE account.id=$1 AND account.enabled
        AND link.issuer=$2 AND link.subject=$3 AND identity_tenant_id('user',account.id)=$4 FOR SHARE OF account`,
      [user.identity_authorization.userId,user.iss,user.sub,tenant.id])).rows[0];
      if (!actor || String(actor.authorization_revision) !== user.identity_authorization.revision
        || String(actor.link_revision) !== user.identity_authorization.linkRevision) reject(401, 'Original identity changed');
      let target;
      if (deleting) {
        target = (await client.query(`SELECT link.user_id FROM identity_subject_links link WHERE link.issuer=$1 AND link.subject=$2
          AND identity_tenant_id('user',link.user_id)=$3 FOR UPDATE`, [body.issuer,body.subject,tenant.id])).rows[0];
      } else {
        target = (await client.query("SELECT id AS user_id FROM users WHERE id=$1 AND identity_tenant_id('user',id)=$2 FOR KEY SHARE", [body.userId,tenant.id])).rows[0];
      }
      if (!target) reject(404, 'Subject-link target not found');
      const roles = await readRoleState(client, user.identity_authorization.userId);
      if (roles.rolesRevision !== user.identity_authorization.rolesRevision || !acceptsRoleAuthentication(roles.authentication, user)) reject(401, 'Original role authority changed');
      if (!sameTenantContext(tenant, await this.revalidate(authorization, user))) reject(401, 'Tenant authority changed');
      const rolesSnapshot = (await client.query('SELECT identity_subject_link_role_state($1) AS state', [user.identity_authorization.userId])).rows[0].state;
      const validUntil = Math.min(user.exp, roles.authentication.required ? user.auth_time + roles.authentication.maxAgeSeconds : user.exp);
      if (!Number.isFinite(validUntil) || validUntil * 1000 <= Date.now()) reject(401, 'Original token assurance expired');
      await client.query("SELECT set_config('opendirectory.actor',$1,true),set_config('opendirectory.subject_link_admission',$2,true)",
        [user.sub, JSON.stringify({ issuer: user.iss, subject: user.sub, context: user.identity_authorization, tenant, validUntil, rolesSnapshot })]);
      const result = deleting
        ? await client.query('DELETE FROM identity_subject_links WHERE issuer=$1 AND subject=$2 RETURNING *', [body.issuer,body.subject])
        : await client.query('INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES($1,$2,$3) RETURNING *', [body.issuer,body.subject,body.userId]);
      if (!sameTenantContext(tenant, await this.revalidate(authorization, user))) reject(401, 'Tenant authority changed');
      return deleting ? undefined : result.rows[0];
    }, { actor: user.sub });
  }
}

module.exports = { SubjectLinks };
