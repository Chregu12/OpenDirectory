'use strict';

const crypto = require('crypto');
const { validUuid, validContext, sameContext } = require('../../../../packages/identity-authorization-contract');
const { sameTenantContext } = require('../../../../packages/tenant-authorization-contract');
const { createTenantStateClient } = require('../../../../packages/oidc-tenant-state');
const { acceptsRoleAuthentication } = require('../../../../packages/role-authentication-contract');
const { AuthorizationState } = require('./AuthorizationState');
const { requireOuReceiver } = require('./AuthorityTenant');
const { mayUseDirectory, requireDirectoryPermissions } = require('./DirectoryAuthority');
const { userFields, userFromRow, USER_COLUMNS } = require('./DirectoryUsers');

function reject(status, message) { throw Object.assign(new Error(message), { status }); }
function namedValues(body, ou = false) {
  const allowed = ou ? ['name','description','parentId'] : ['name','description'];
  if (body && typeof body === 'object' && !Array.isArray(body) && !body.name) reject(400, 'name is required');
  if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).some(key => !allowed.includes(key))
    || typeof body.name !== 'string' || !body.name.trim() || body.name.length > 255 || /[\u0000-\u001f\u007f]/.test(body.name)) reject(400, 'A bounded name and exact directory fields are required');
  if (body.description !== undefined && body.description !== null && (typeof body.description !== 'string' || body.description.length > 2000
    || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(body.description))) reject(400, 'Invalid directory description');
  if (ou && body.parentId !== undefined && body.parentId !== null && !validUuid(body.parentId)) reject(400, 'Canonical OU parent required');
  return { name:body.name.trim(),description:body.description?.trim() || null,...(ou ? {parentId:body.parentId?.toLowerCase() || null} : {}) };
}
function iso(value) { return value instanceof Date ? value.toISOString() : value || undefined; }

class DirectoryCreator {
  constructor(database, { issuer = process.env.OIDC_ISSUER || 'http://localhost:3001', revalidate = createTenantStateClient(), newResourceId = () => crypto.randomUUID() } = {}) {
    this.database = database; this.issuer = issuer; this.revalidate = revalidate; this.newResourceId = newResourceId;
  }

  async create(kind, values, user, authorization, operation) {
    if (!this.database.isAvailable()) reject(503, 'Canonical directory storage required');
    const permission = {user:'users.create',group:'groups.create',ou:'ous.create'}[kind];
    if (!permission || user?.actor_type !== 'user' || user.iss !== this.issuer || !validContext(user.identity_authorization)
      || !mayUseDirectory(user, [permission])) reject(403, 'Canonical directory creator required');
    const resourceId = this.newResourceId(); if (!validUuid(resourceId)) reject(503, 'Creation identifier unavailable');
    const tenant = await this.revalidate(authorization, user);
    return this.database.transaction(async client => {
      const current = (await client.query('SELECT id,version,generation FROM identity_tenants WHERE id=$1 AND enabled FOR SHARE', [tenant.id])).rows[0];
      if (!current || !sameTenantContext(tenant, {id:current.id,version:String(current.version),generation:String(current.generation)})) reject(401, 'Tenant authority changed');
      if (kind === 'ou') { await requireOuReceiver(client); await client.query('SELECT identity_directory_ou_lock($1)', [tenant.id]); }
      if (!(await client.query('SELECT id FROM users WHERE id=$1 FOR SHARE', [user.identity_authorization.userId])).rows.length) reject(401, 'Original creator unavailable');
      const source = await new AuthorizationState({transaction:callback=>callback(client)}).state(user.iss,user.sub);
      if (!source.active || !sameContext(source.context,user.identity_authorization) || !sameTenantContext(source.tenant,tenant)
        || !acceptsRoleAuthentication(source.authentication,user)) reject(401, 'Original creator authority changed');
      await requireDirectoryPermissions(client, user, [permission]);
      await client.query("SET LOCAL statement_timeout = '15s'");
      if (kind === 'ou' && values.parentId && !(await client.query("SELECT id FROM ous WHERE id=$1 AND identity_tenant_id('ou',id)=$2 FOR KEY SHARE", [values.parentId,tenant.id])).rows.length) reject(404, 'OU parent not found');
      if (kind === 'ou' && values.parentId) {
        const ancestors = (await client.query(`WITH RECURSIVE ancestors AS (
          SELECT id,parent_id,ARRAY[id] AS path FROM ous WHERE id=$1 AND identity_tenant_id('ou',id)=$2
          UNION ALL SELECT parent.id,parent.parent_id,ancestors.path||parent.id FROM ous parent JOIN ancestors ON parent.id=ancestors.parent_id
          WHERE cardinality(ancestors.path)<256 AND NOT parent.id=ANY(ancestors.path) AND identity_tenant_id('ou',parent.id)=$2)
          SELECT unit.id,unit.parent_id FROM ancestors JOIN ous unit ON unit.id=ancestors.id ORDER BY unit.id FOR SHARE OF unit`, [values.parentId,tenant.id])).rows;
        const nodes = new Map(ancestors.map(unit => [unit.id,unit.parent_id])); const visited = new Set(); let parent = values.parentId;
        while (parent) {
          if (!nodes.has(parent) || visited.has(parent)) reject(503, 'Incoherent OU parent hierarchy');
          if (visited.size >= 255) reject(409, 'OU hierarchy depth exceeded');
          visited.add(parent); parent = nodes.get(parent);
        }
      }
      if (!sameTenantContext(tenant,await this.revalidate(authorization,user))) reject(401, 'Tenant authority changed');
      const rolesSnapshot = (await client.query('SELECT identity_subject_link_role_state($1) AS state', [user.identity_authorization.userId])).rows[0].state;
      const validUntil = Math.min(user.exp, source.authentication.required ? user.auth_time + source.authentication.maxAgeSeconds : user.exp);
      if (!Number.isFinite(validUntil) || validUntil * 1000 <= Date.now()) reject(401, 'Original creator assurance expired');
      const proof = {issuer:user.iss,subject:user.sub,context:user.identity_authorization,tenant,rolesSnapshot,validUntil,resource:{kind,id:resourceId.toLowerCase(),values}};
      await client.query("SELECT set_config('opendirectory.directory_creation',$1,true)", [JSON.stringify(proof)]);
      if (kind === 'ou') await client.query('SELECT identity_directory_ou_creation_admit($1::jsonb)', [JSON.stringify(proof)]);
      const result = await operation(client,proof.resource.id);
      if (!result.rows || result.rows.length !== 1) reject(409, 'Directory creation not confirmed');
      const receipt = await client.query(`SELECT ownership.resource_id FROM identity_tenant_ownership ownership
        JOIN identity_tenant_events event ON event.tenant_id=ownership.tenant_id AND event.action='resource-created'
          AND event.details->>'kind'=$1 AND event.details->>'resourceId'=$2 AND event.details->>'generation'=ownership.generation::text
        JOIN identity_tenant_outbox outbox ON outbox.id=event.id AND outbox.tenant_id=event.tenant_id AND outbox.action=event.action
        WHERE ownership.resource_kind=$1 AND ownership.resource_id=$2::uuid AND ownership.tenant_id=$3::uuid
          AND ownership.reason='Original-token-bound new-resource creation'
          AND event.actor=jsonb_build_object('issuer',$4::text,'subject',$5::text,'userId',$6::text)
          AND event.details->>'contentSha256'=encode(sha256(convert_to($7::jsonb::text,'UTF8')),'hex') LIMIT 1`,
      [kind,proof.resource.id,tenant.id,user.iss,user.sub,user.identity_authorization.userId,JSON.stringify(values)]);
      if (receipt.rows.length !== 1) reject(503, 'Tenant-bound creation receipt unavailable');
      if (!sameTenantContext(tenant,await this.revalidate(authorization,user))) reject(401, 'Tenant authority changed');
      return result.rows[0];
    }, {actor:user.sub});
  }

  async user(body, user, authorization) {
    const fields = userFields(body,true);
    const values = {username:fields.username,email:fields.email,displayName:fields.displayName ?? null,department:fields.department ?? null,title:fields.title ?? null,enabled:false};
    return userFromRow(await this.create('user',values,user,authorization,(client,resourceId)=>client.query(`INSERT INTO users(id,username,email,display_name,department,title,enabled)
      VALUES($1,$2,$3,$4,$5,$6,false) RETURNING ${USER_COLUMNS}`, [resourceId,values.username,values.email,values.displayName,values.department,values.title])));
  }

  async group(body, user, authorization) {
    const values = namedValues(body);
    const row = await this.create('group',values,user,authorization,(client,resourceId)=>client.query('INSERT INTO groups(id,name,description) VALUES($1,$2,$3) RETURNING *',[resourceId,values.name,values.description]));
    return {id:row.id,name:row.name,description:row.description ?? undefined,members:[],createdAt:iso(row.created_at),revision:String(row.revision)};
  }

  async ou(body, user, authorization) {
    const values = namedValues(body,true);
    const row = await this.create('ou',values,user,authorization,(client,resourceId)=>client.query('INSERT INTO ous(id,name,description,parent_id) VALUES($1,$2,$3,$4) RETURNING *',[resourceId,values.name,values.description,values.parentId]));
    return {id:row.id,name:row.name,description:row.description ?? undefined,parentId:row.parent_id ?? undefined,createdAt:iso(row.created_at),updatedAt:iso(row.updated_at),revision:String(row.revision),memberCount:0};
  }
}

module.exports = { DirectoryCreator };
