'use strict';
const { validContext, sameContext } = require('../../../../packages/identity-authorization-contract');
const { acceptsRoleAuthentication } = require('../../../../packages/role-authentication-contract');
const { getIdentityPermissions } = require('./middleware/identityAccess');
const { companyOwner } = require('./CompanyOwner');
const { authorityTenant } = require('./AuthorityTenant');
const { readRoleState } = require('./RoleState');
const { PERMISSIONS, fail } = require('./CompanyRoleContract');
const FRESH = { required: true, maxAgeSeconds: 300 };
async function configured(client) { return (await client.query("SELECT to_regclass('identity_company_roles') IS NOT NULL AS configured")).rows[0]?.configured === true; }
async function receiving(client) {
  try { await client.query('SELECT identity_company_role_receiving()'); }
  catch (error) { throw Object.assign(new Error('company_role_authority_unavailable'), { status: 503, cause: error }); }
}
async function lock(client, tenant) {
  // Old isolated kernels have no role storage; a configured receiver must always validate.
  if (!await configured(client)) return;
  await client.query('SELECT identity_company_roles_lock($1::uuid)', [tenant]); await receiving(client);
}
async function actorProof(client, user, { fresh = true } = {}) {
  if (user?.actor_type !== 'user' || !validContext(user.identity_authorization)) fail(403, 'company_role_human_required');
  await client.query("SET LOCAL timezone='UTC'");
  const tenantId = await authorityTenant(client, { ...user.identity_authorization, issuer: user.iss, subject: user.sub });
  const state = await readRoleState(client, user.identity_authorization.userId);
  if (state.rolesRevision !== user.identity_authorization.rolesRevision) fail(401, 'company_role_actor_changed');
  if (!acceptsRoleAuthentication(state.authentication, user) || fresh && !acceptsRoleAuthentication(FRESH, user)) fail(428, 'fresh_mfa_required');
  const tenant = (await client.query('SELECT id,version::text,generation::text FROM identity_tenants WHERE id=$1 AND enabled', [tenantId])).rows[0];
  if (!tenant) fail(401, 'company_role_tenant_changed');
  const validUntil = Math.min(user.exp, fresh ? user.auth_time + 300 : Infinity, state.authentication.required ? user.auth_time + state.authentication.maxAgeSeconds : Infinity);
  if (!Number.isSafeInteger(validUntil) || validUntil * 1000 <= Date.now()) fail(401, 'company_role_assurance_expired');
  return { issuer: user.iss, subject: user.sub, context: structuredClone(user.identity_authorization), tenant,
    ...(user.mfa_authorization?{mfa:structuredClone(user.mfa_authorization)}:{}),rolesSnapshot: (await client.query('SELECT identity_subject_link_role_state($1) AS state', [user.identity_authorization.userId])).rows[0].state, validUntil };
}
async function managerProof(client,user,{fresh=true,manage=true}={}) {
  const proof=await actorProof(client,user,{fresh});const state=await readRoleState(client,user.identity_authorization.userId);
  if(!await companyOwner(client,user)&&!getIdentityPermissions({roles:state.roles}).includes(manage?'identities.roles.manage':'identities.roles.read'))fail(403,'company_role_manager_required');
  return proof;
}
function accepted(user,source) {
  if(!source.activationId)return acceptsRoleAuthentication(FRESH,user);
  return acceptsRoleAuthentication({required:true,maxAgeSeconds:86400},user)&&source.mfaRevision===user.mfa_authorization.revision
    && Number(source.authTime)<=user.auth_time&&source.issuer===user.iss&&source.subject===user.sub&&sameContext(source.actorContext,user.identity_authorization);
}
function deadline(user,captured) {
  return captured?Math.min(...captured.grants.map(grant=>Math.min(Number(grant.source.validUntil),grant.source.activationId?Infinity:user.auth_time+300))):user.exp;
}
async function permissions(client,user) {
  if(user?.actor_type!=='user'||!validContext(user.identity_authorization)||!acceptsRoleAuthentication({required:true,maxAgeSeconds:86400},user)||!await configured(client))return [];
  await receiving(client);const tenant=await authorityTenant(client,{...user.identity_authorization,issuer:user.iss,subject:user.sub});
  const rows=(await client.query('SELECT permission,identity_company_role_sources($1::uuid,$2::uuid,permission,NULL,NULL) AS sources FROM unnest($3::text[]) permission',[user.identity_authorization.userId,tenant,PERMISSIONS])).rows;
  if(rows.some(row=>!Array.isArray(row.sources)||row.sources.length>1000))fail(503,'company_role_source_limit');
  return rows.filter(row=>row.sources.some(source=>accepted(user,source))).map(row=>row.permission);
}
async function capture(client, user, required, resource = null) {
  await receiving(client); const tenant = await authorityTenant(client, { ...user.identity_authorization, issuer: user.iss, subject: user.sub });
  const grants = [];
  for (const permission of required) {
    const actual = (await client.query('SELECT identity_company_role_sources($1::uuid,$2::uuid,$3,$4,$5::uuid) AS sources', [user.identity_authorization.userId, tenant, permission, resource?.kind || null, resource?.id || null])).rows[0]?.sources;
    if(!Array.isArray(actual)||actual.length>1000)fail(503,'company_role_source_limit');
    const sources=actual.filter(source=>accepted(user,source));
    if(!sources.length){if(actual.length&&!acceptsRoleAuthentication(FRESH,user))fail(428,'fresh_mfa_required');fail(403,'company_role_scope_required');}
    if (!resource) { grants.push(...sources.map(source => ({ permission, source }))); continue; }
    const selected = [...sources].sort((a, b) => deadline(user,{grants:[{source:b}]}) - deadline(user,{grants:[{source:a}]}) || a.id.localeCompare(b.id))[0];
    grants.push({ permission, source: selected });
  }
  return { kind: resource?.kind || null, id: resource?.id || null, grants };
}
async function governance(client, user, kind, id, parentId = null) {
  if (!await configured(client)) return undefined;
  if (!(await client.query('SELECT identity_company_role_protected($1,$2::uuid,$3::uuid) AS protected', [kind, id, parentId])).rows[0]?.protected) return undefined;
  return managerProof(client, user);
}
module.exports = { FRESH, configured, receiving, lock, actorProof, managerProof, accepted, deadline, permissions, capture, governance };
