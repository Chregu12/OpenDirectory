'use strict';

const { ROLES, PROTECTED, MFA_LOCKED_ROLES } = require('../../../../packages/directory-role-contract');
const { validContext, sameContext } = require('../../../../packages/identity-authorization-contract');
const { validPolicy, readRoleState } = require('./RoleState');
const { acceptsRoleAuthentication } = require('../../../../packages/role-authentication-contract');
const { getIdentityPermissions } = require('./middleware/identityAccess');
const { AuthorityCommand } = require('./AuthorityCommand');
function fail(status, code) { throw Object.assign(new Error(code), { status, code }); }
function policyRole(value) { if (!ROLES.includes(value)) fail(400, 'catalog_role_required'); return value; }
function policyEtag(role, version) { return `"od-role-authentication:${role}:${version}"`; }
function fresh(user) { return acceptsRoleAuthentication({ required: true, maxAgeSeconds: 300 }, user); }
function protectedRole(role) { return role === 'user' || PROTECTED.includes(role); }
class RoleAuthentication {
  constructor(database, options) { this.database = database; this.commands = new AuthorityCommand(database, options); }
  authority(user, permission) {
    if (user?.actor_type !== 'user' || !validContext(user.identity_authorization) || typeof user.iss !== 'string' || !user.iss
      || typeof user.sub !== 'string' || !user.sub.trim()) fail(403, 'canonical_human_required');
    if (!getIdentityPermissions(user).includes(permission)) fail(403, 'forbidden');
    return JSON.stringify({ issuer: user.iss, subject: user.sub, userId: user.identity_authorization.userId });
  }
  view(row, user) {
    validPolicy(row);
    const allowed = getIdentityPermissions(user).includes('authentication.policies.manage') && !MFA_LOCKED_ROLES.includes(row.role)
      && (!protectedRole(row.role) || user.roles?.includes('admin'));
    return { role: row.role, version: String(row.version), required: row.mfa_required, maxAgeSeconds: row.max_age_seconds,
      protected: protectedRole(row.role), locked: MFA_LOCKED_ROLES.includes(row.role), canManage: !!allowed && fresh(user), requiresFreshMfa: !!allowed && !fresh(user) };
  }
  async get(role, user) {
    policyRole(role); this.authority(user, 'authentication.policies.read');
    return this.database.transaction(async client => this.view((await client.query('SELECT * FROM identity_role_authentication WHERE role=$1', [role])).rows[0], user), { readOnly: true });
  }
  async currentActor(client, user) {
    const row = (await client.query(`SELECT users.id,identity_tenant_user_enabled(users.id) AS enabled,users.authorization_revision AS revision,identity_subject_links.authorization_revision AS link_revision
      FROM users JOIN identity_subject_links ON users.id=identity_subject_links.user_id WHERE issuer=$1 AND subject=$2`, [user.iss, user.sub])).rows[0];
    if (!row || !row.enabled) fail(401, 'authorization_changed');
    const state = await readRoleState(client, row.id);
    if (!sameContext({ userId: row.id,revision: String(row.revision),linkRevision: String(row.link_revision),rolesRevision: state.rolesRevision }, user.identity_authorization)
      || !getIdentityPermissions({ roles: state.roles }).includes('authentication.policies.manage') || !acceptsRoleAuthentication(state.authentication,user)) fail(401, 'authorization_changed');
  }
  async change(role, etag, body, user, authorization) {
    policyRole(role); const actor = this.authority(user, 'authentication.policies.manage');
    if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).length !== 3
      || Object.keys(body).some(field => !['required','maxAgeSeconds','reason'].includes(field)) || typeof body.required !== 'boolean'
      || !Number.isInteger(body.maxAgeSeconds) || body.maxAgeSeconds < 300 || body.maxAgeSeconds > 86400
      || typeof body.reason !== 'string' || body.reason.trim().length < 10 || body.reason.length > 500 || /[\u0000-\u001f\u007f]/.test(body.reason)) fail(400, 'invalid_authentication_policy');
    if (!etag) fail(428, 'version_required');
    return this.commands.run(user, authorization, async client => {
      const current = validPolicy((await client.query('SELECT * FROM identity_role_authentication WHERE role=$1 FOR UPDATE', [role])).rows[0]);
      if (etag !== policyEtag(role, String(current.version))) fail(412, 'authentication_policy_changed');
      if (MFA_LOCKED_ROLES.includes(role)) fail(409, 'fixed_authentication_policy');
      if (protectedRole(role) && !user.roles?.includes('admin')) fail(403, 'global_administrator_required');
      if (!fresh(user)) fail(428, 'fresh_mfa_required');
      await this.currentActor(client,user);
      await client.query("SELECT set_config('opendirectory.authentication_reason',$1,true)", [body.reason.trim()]);
      const result = await client.query('UPDATE identity_role_authentication SET mfa_required=$2,max_age_seconds=$3,version=version+1 WHERE role=$1 RETURNING *', [role, body.required, body.maxAgeSeconds]);
      return this.view(result.rows[0], user);
    }, { actor }, { required: true, maxAgeSeconds: 300 });
  }
}
module.exports = { RoleAuthentication, policyEtag, validPolicy };
