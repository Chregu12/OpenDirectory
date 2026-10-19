'use strict';

const { ROLES, PROTECTED } = require('../../../../packages/directory-role-contract');
const { sameContext, validContext, validRevision } = require('../../../../packages/identity-authorization-contract');
const { acceptsRoleAuthentication } = require('../../../../packages/role-authentication-contract');
const { createAccessStateClient } = require('../../../../packages/oidc-access-state');
const { getIdentityPermissions } = require('./middleware/identityAccess');
const { readRoleState } = require('./RoleState');
const { beginAuthorityCheckpoint, checkpointError } = require('./AuthorityCheckpoint');
function fail(status, code) { throw Object.assign(new Error(code), { status, code }); }
function catalogRole(role) { if (!ROLES.includes(role)) fail(400,'catalog_role_required'); return role; }
function activationEtag(role, version) { return `"od-role-activation:${role}:${version}"`; }
function validActivationPolicy(row) {
  if (!row || !ROLES.includes(row.role) || !validRevision(String(row.version)) || typeof row.activation_required !== 'boolean'
    || !Number.isInteger(row.max_duration_seconds) || row.max_duration_seconds < 60 || row.max_duration_seconds > 28800
    || !Array.isArray(row.reviewer_user_ids) || row.reviewer_user_ids.length>20
    || row.reviewer_user_ids.some((identifier,index) => typeof identifier!=='string' || !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(identifier)
      || index>0 && row.reviewer_user_ids[index-1]>=identifier)
    || row.role === 'admin' && row.activation_required && !row.reviewer_user_ids.length
    || row.role === 'user' && (row.activation_required || row.max_duration_seconds !== 28800 || row.reviewer_user_ids.length)) fail(503,'activation_policy_unavailable');
  return row;
}
const fresh = user => acceptsRoleAuthentication({ required:true,maxAgeSeconds:300 },user);
class PrivilegedAccessPolicy {
  constructor(database, { revalidate } = {}) {
    this.database = database;
    const accessState = createAccessStateClient();
    this.revalidate = revalidate || ((user,authorization) => accessState(authorization,user));
  }
  authority(user, permission) {
    if (user?.actor_type !== 'user' || !validContext(user.identity_authorization) || typeof user.iss !== 'string' || !user.iss
      || typeof user.sub !== 'string' || !user.sub.trim()) fail(403,'canonical_human_required');
    if (!getIdentityPermissions(user).includes(permission)) fail(403,'forbidden');
    return JSON.stringify({ issuer:user.iss,subject:user.sub,userId:user.identity_authorization.userId });
  }
  view(row, user) {
    validActivationPolicy(row);
    const allowed = row.role !== 'user' && getIdentityPermissions(user).includes('pim.policies.manage')
      && (!PROTECTED.includes(row.role) || user.roles?.includes('admin'));
    return { role:row.role,version:String(row.version),required:row.activation_required,maxDurationSeconds:row.max_duration_seconds,reviewerUserIds:row.reviewer_user_ids,
      protected:PROTECTED.includes(row.role),locked:row.role === 'user',canManage:!!allowed && fresh(user),requiresFreshMfa:!!allowed && !fresh(user) };
  }
  async get(role, user) {
    catalogRole(role); this.authority(user,'pim.policies.read');
    return this.database.transaction(async client => this.view((await client.query('SELECT * FROM identity_role_activation_policies WHERE role=$1',[role])).rows[0],user),{ readOnly:true });
  }
  async catalog() {
    return this.database.transaction(async client => {
      const rows = (await client.query('SELECT * FROM identity_role_activation_policies ORDER BY role COLLATE "C"')).rows;
      if (rows.length !== ROLES.length || rows.some((row,index) => validActivationPolicy(row).role !== [...ROLES].sort()[index])) fail(503,'activation_policy_unavailable');
      return new Map(rows.map(row => [row.role,row]));
    },{ readOnly:true });
  }
  async currentActor(client, user) {
    const row = (await client.query(`SELECT users.id,users.enabled,users.authorization_revision AS revision,link.authorization_revision AS link_revision
      FROM users JOIN identity_subject_links link ON users.id=link.user_id WHERE issuer=$1 AND subject=$2`,[user.iss,user.sub])).rows[0];
    if (!row?.enabled) fail(401,'authorization_changed');
    const state = await readRoleState(client,row.id);
    if (!sameContext({ userId:row.id,revision:String(row.revision),linkRevision:String(row.link_revision),rolesRevision:state.rolesRevision },user.identity_authorization)
      || !getIdentityPermissions({ roles:state.roles }).includes('pim.policies.manage') || !acceptsRoleAuthentication(state.authentication,user)) fail(401,'authorization_changed');
  }
  async change(role, etag, body, user, authorization) {
    catalogRole(role); const actor = this.authority(user,'pim.policies.manage');
    if (!body || typeof body !== 'object' || Array.isArray(body) || ![4,5].includes(Object.keys(body).length)
      || Object.keys(body).some(key => !['required','maxDurationSeconds','reason','acknowledgeInvalidation','reviewerUserIds'].includes(key))
      || typeof body.required !== 'boolean' || !Number.isInteger(body.maxDurationSeconds) || body.maxDurationSeconds < 60 || body.maxDurationSeconds > 28800
      || body.acknowledgeInvalidation !== true || typeof body.reason !== 'string' || body.reason.trim().length < 10 || body.reason.length > 500
      || /[\u0000-\u001f\u007f]/.test(body.reason)) fail(400,'invalid_activation_policy');
    const reviewers = body.reviewerUserIds === undefined ? [] : body.reviewerUserIds;
    if (!Array.isArray(reviewers) || reviewers.length>20 || reviewers.some((identifier,index) => typeof identifier!=='string'
      || !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(identifier) || index>0 && reviewers[index-1]>=identifier)
      || reviewers.length && (!body.required || !PROTECTED.includes(role)) || role==='admin' && body.required && !reviewers.length) fail(400,'invalid_activation_reviewers');
    if (!etag) fail(428,'version_required');
    return this.database.transaction(async client => {
      const checkpoint = await beginAuthorityCheckpoint(client,user);
      const current = validActivationPolicy((await client.query('SELECT * FROM identity_role_activation_policies WHERE role=$1 FOR UPDATE',[role])).rows[0]);
      if (etag !== activationEtag(role,String(current.version))) fail(412,'activation_policy_changed');
      if (role === 'user') fail(409,'fixed_activation_policy');
      if (PROTECTED.includes(role) && !user.roles?.includes('admin')) fail(403,'global_administrator_required');
      if (!fresh(user)) fail(428,'fresh_mfa_required');
      await this.currentActor(client,user); await this.revalidate(user,authorization);
      for(const identifier of reviewers) {
        if(identifier===user.identity_authorization.userId) fail(403,'independent_reviewer_required');
        const recipient=(await client.query('SELECT enabled FROM users WHERE id=$1 FOR SHARE',[identifier])).rows[0];
        const state=recipient?.enabled ? await readRoleState(client,identifier) : null;
        if(!state?.roles.some(held => held!==role && ['admin','pim-approver'].includes(held))) fail(409,'reviewer_unavailable');
      }
      if(role==='admin' && body.required) {
        const eligible=await client.query(`SELECT eligibility.id FROM identity_pim_eligibilities eligibility JOIN users ON users.id=eligibility.user_id
          WHERE eligibility.role='admin' AND eligibility.revoked_at IS NULL AND eligibility.expires_at>clock_timestamp()+interval '60 seconds'
          AND users.enabled AND eligibility.user_id<>ALL($1::uuid[]) ORDER BY eligibility.expires_at,eligibility.id LIMIT 1 FOR SHARE OF eligibility,users`,[reviewers]);
        if(!eligible.rows.length) fail(409,'activation_path_unavailable');
      }
      await client.query("SELECT set_config('opendirectory.activation_reason',$1,true)",[body.reason.trim()]);
      const result = await client.query('UPDATE identity_role_activation_policies SET activation_required=$2,max_duration_seconds=$3,reviewer_user_ids=$4,version=version+1 WHERE role=$1 RETURNING *',[role,body.required,body.maxDurationSeconds,reviewers]);
      await this.revalidate(user,authorization);
      if (!fresh(user)) fail(428,'fresh_mfa_required');
      await checkpoint({ required:true,maxAgeSeconds:300 });
      return this.view(result.rows[0],user);
    },{ actor }).catch(checkpointError);
  }
}
module.exports = { PrivilegedAccessPolicy, activationEtag, validActivationPolicy };
