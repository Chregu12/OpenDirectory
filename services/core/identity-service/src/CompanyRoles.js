'use strict';
const { randomUUID } = require('node:crypto');
const Contract = require('./CompanyRoleContract');
const Authority = require('./CompanyRoleAuthority');
const { AuthorityCommand } = require('./AuthorityCommand');
const { DirectoryCreator } = require('./DirectoryCreator');
const { getIdentityPermissions } = require('./middleware/identityAccess');
const { authorityTenant } = require('./AuthorityTenant');
const iso = value => value ? new Date(value).toISOString() : null;
function role(row) { return { id: row.id, tenantId: row.tenant_id, name: row.name, description: row.description, permissions: row.permissions, maxDurationSeconds: row.max_duration_seconds, enabled: row.enabled, revision: String(row.revision), createdAt: iso(row.created_at), updatedAt: iso(row.updated_at) }; }
function grant(row) { return { id: row.id, tenantId: row.tenant_id, roleId: row.role_id, roleRevision: String(row.role_revision), targetType: row.target_type, targetId: row.target_id, scopeType: row.scope_type, ouId: row.ou_id,
  revision: String(row.revision), createdAt: iso(row.created_at), expiresAt: iso(row.expires_at), revokedAt: iso(row.revoked_at), status: row.revoked_at ? 'revoked' : !row.definition_current ? 'definition-changed' : row.expired ? 'expired' : row.effective ? 'active' : 'inactive' }; }
function error(failure) {
  if (!failure.status && ['23503','23505','23514','42501','28000','40P01','55P03'].includes(failure.code)) failure.status = ({23503:404,23505:409,23514:409,42501:503,28000:401,'40P01':409,'55P03':409})[failure.code];
  throw failure;
}
class CompanyRoles {
  constructor(database, options = {}) {
    this.database = database; this.options = options;

  }
  commands(user) {
    const database = { transaction: (operation, settings) => this.database.transaction(async client => {
      const tenant = await authorityTenant(client, { ...user.identity_authorization, issuer: user.iss, subject: user.sub }, { write: true });
      await Authority.lock(client, tenant); return operation(client);
    }, settings) };
    return new AuthorityCommand(database, this.options);
  }
  async permissions(user) {
    if (!this.database.isAvailable()) return [];
    try { return await this.database.transaction(async client => { if (!await Authority.configured(client)) return []; await Authority.managerProof(client,user,{fresh:false,manage:false});await Authority.receiving(client);
      try{await Authority.managerProof(client,user,{fresh:false});return ['company.roles.read','company.roles.manage'];}catch(failure){if(![403,428].includes(failure.status))throw failure;return ['company.roles.read'];} }, { readOnly: true }); }
    catch (failure) { if ([401,403,428].includes(failure.status)) return []; throw failure; }
  }
  async read(user, authorization, operation) {
    user = structuredClone(user); const commands = this.commands(user); await commands.revalidate(user, authorization);
    let deadline;const result = await this.database.transaction(async client => {
      const proof = await Authority.managerProof(client,user,{fresh:false,manage:false}); deadline=proof.validUntil;await Authority.receiving(client);
      return operation(client, proof.tenant.id);
    }, { readOnly: true });
    await commands.revalidate(user,authorization);if(!Number.isFinite(deadline)||deadline*1000<=Date.now())Contract.fail(401,'company_role_assurance_expired');return result;
  }
  async list(query, user, authorization) {
    const page = Contract.page(query);
    return this.read(user, authorization, async (client, tenant) => {
      const where = "tenant_id=$1 AND ($2='' OR strpos(lower(concat_ws(' ',name,description)),lower($2))>0)";
      const total = Number((await client.query('SELECT count(*) AS count FROM identity_company_roles WHERE ' + where, [tenant, page.search])).rows[0].count);
      const rows = (await client.query('SELECT * FROM identity_company_roles WHERE ' + where + ' ORDER BY lower(name),id LIMIT 25 OFFSET $3', [tenant, page.search, (page.page - 1) * 25])).rows;
      const groups = (await client.query("SELECT collection.id,collection.name,collection.revision::text FROM groups collection JOIN identity_tenant_ownership namespace ON namespace.resource_kind='group' AND namespace.resource_id=collection.id AND namespace.tenant_id=$1 JOIN identity_company_role_groups protected ON protected.group_id=collection.id AND protected.tenant_id=$1 AND protected.generation=namespace.generation WHERE identity_tenant_id('group',collection.id)=$1 ORDER BY lower(collection.name),collection.id LIMIT 1001", [tenant])).rows;
      let manageable=true;try{await Authority.managerProof(client,user);}catch(failure){if(![403,428].includes(failure.status))throw failure;manageable=false;}
      return { schemaVersion: 1, companyRolesProtocol: 1, actorUserId: user.identity_authorization.userId, tenantId: tenant, permissions: [...Contract.PERMISSIONS], ouPermissions: [...Contract.OU_PERMISSIONS],
        canManage:manageable,canCreateRoleGroup:manageable&&(getIdentityPermissions(user).includes('groups.create') || Boolean(await require('./CompanyOwner').companyOwner(client,user))),
        roles: rows.map(role), total, page: page.page, limit: 25, groups: groups.slice(0,1000), groupsTruncated: groups.length>1000 };
    }).catch(error);
  }
  async detail(id, query, user, authorization) {
    Contract.identifier(id); const page = Contract.page(query); if (page.search) Contract.fail(400, 'grant_search_not_supported');
    return this.read(user, authorization, async (client, tenant) => {
      const definition = (await client.query('SELECT * FROM identity_company_roles WHERE id=$1 AND tenant_id=$2', [id, tenant])).rows[0]; if (!definition) Contract.fail(404, 'company_role_not_found');
      const total = Number((await client.query('SELECT count(*) AS count FROM identity_company_role_grants WHERE role_id=$1 AND tenant_id=$2', [id,tenant])).rows[0].count);
      const rows = (await client.query(`SELECT assignment.*,definition.enabled AND definition.revision=assignment.role_revision AS definition_current,assignment.expires_at<=clock_timestamp() AS expired,
        CASE WHEN assignment.target_type='user' THEN EXISTS(SELECT 1 FROM jsonb_array_elements(identity_company_role_sources(assignment.target_id,$2,definition.permissions[1],NULL,NULL)) source WHERE source->>'id'=assignment.id::text)
        ELSE EXISTS(SELECT 1 FROM groups collection JOIN identity_tenant_ownership namespace ON namespace.resource_kind='group' AND namespace.resource_id=collection.id AND namespace.tenant_id=$2 JOIN identity_company_role_groups protected ON protected.group_id=collection.id AND protected.generation=namespace.generation WHERE collection.id=assignment.target_id AND namespace.generation=assignment.target_generation AND identity_tenant_id('group',collection.id)=$2) AND (assignment.scope_type='tenant' OR EXISTS(SELECT 1 FROM ous unit JOIN identity_tenant_ownership scope ON scope.resource_kind='ou' AND scope.resource_id=unit.id AND scope.tenant_id=$2 JOIN identity_company_role_ous protected ON protected.ou_id=unit.id AND protected.tenant_id=$2 AND protected.generation=scope.generation WHERE unit.id=assignment.ou_id AND scope.generation=assignment.ou_generation AND identity_tenant_id('ou',unit.id)=$2)) END AS effective
        FROM identity_company_role_grants assignment JOIN identity_company_roles definition ON definition.id=assignment.role_id WHERE assignment.role_id=$1 AND assignment.tenant_id=$2 ORDER BY assignment.created_at DESC,assignment.id DESC LIMIT 25 OFFSET $3`, [id,tenant,(page.page-1)*25])).rows;
      return { schemaVersion:1,actorUserId:user.identity_authorization.userId,tenantId:tenant,role:role(definition),grants:rows.map(grant),total,page:page.page,limit:25 };
    }).catch(error);
  }
  async history(id, query, user, authorization) {
    Contract.identifier(id);const page=Contract.page(query);if(page.search)Contract.fail(400,'role_history_search_not_supported');
    return this.read(user,authorization,async(client,tenant)=>{
      if(!(await client.query('SELECT id FROM identity_company_roles WHERE id=$1 AND tenant_id=$2',[id,tenant])).rows.length)Contract.fail(404,'company_role_not_found');
      const where="tenant_id=$1 AND (resource_id=$2 OR after_state->>'role_id'=$2::text OR before_state->>'role_id'=$2::text)";
      const total=Number((await client.query('SELECT count(*) AS count FROM identity_company_role_events WHERE '+where,[tenant,id])).rows[0].count);
      const rows=(await client.query("SELECT event.*,outbox.status AS delivery_status FROM identity_company_role_events event LEFT JOIN identity_company_role_outbox outbox USING(id) WHERE event."+where+" ORDER BY event.created_at DESC,event.id DESC LIMIT 25 OFFSET $3",[tenant,id,(page.page-1)*25])).rows;
      if(rows.some(row=>row.delivery_status!=='pending'))Contract.fail(503,'company_role_history_receipt_unavailable');
      return {schemaVersion:1,actorUserId:user.identity_authorization.userId,tenantId:tenant,roleId:id,total,page:page.page,limit:25,events:rows.map(row=>({id:row.id,action:row.action,resourceId:row.resource_id,actorUserId:row.actor.context.userId,reason:row.reason,createdAt:iso(row.created_at),deliveryStatus:'pending'}))};
    }).catch(error);
  }
  async change(action, id, values, expected, user, authorization, roleId = null) {
    user = structuredClone(user);
    const body = action === 'role-create' ? Contract.definition(values,true) : action === 'role-update' ? Contract.definition(values) : action === 'grant-create' ? Contract.assignment(values) : Contract.decision(values);
    const revision = action === 'role-create' || action === 'group-protect' ? null : Contract.expected(action === 'grant-revoke' ? 'grant' : 'role', expected, roleId || id);
    return this.commands(user).run(user, authorization, async client => {
      const proof = await Authority.managerProof(client, user); await Authority.receiving(client);
      if (revision) {
        const table = action === 'grant-revoke' ? 'identity_company_role_grants' : 'identity_company_roles';
        const row = (await client.query('SELECT revision::text FROM ' + table + ' WHERE id=$1 AND tenant_id=$2', [roleId || id,proof.tenant.id])).rows[0];
        if (!row) Contract.fail(404, 'company_role_not_found'); if (row.revision !== revision) Contract.fail(412, 'company_role_changed');
      }
      if(action==='grant-create'&&(body.targetType==='user'&&body.targetId===proof.context.userId||body.targetType==='group'&&(await client.query('SELECT 1 FROM group_members WHERE group_id=$1 AND user_id=$2',[body.targetId,proof.context.userId])).rows.length))Contract.fail(403,'independent_company_role_recipient_required');
      const command = { action, id, eventId:randomUUID(),actor:proof,values:body,expectedRevision:revision,roleId };
      const eventId = (await client.query('SELECT identity_company_role_change($1::jsonb) AS id', [JSON.stringify(command)])).rows[0]?.id;
      const event = (await client.query("SELECT event.* FROM identity_company_role_events event JOIN identity_company_role_outbox outbox USING(id) WHERE event.id=$1 AND event.tenant_id=$2 AND event.actor=$3::jsonb AND event.transaction_id=txid_current() AND outbox.tenant_id=event.tenant_id AND outbox.status='pending'", [eventId, proof.tenant.id, JSON.stringify(proof)])).rows[0];
      if (!event || event.action !== action || event.resource_id !== id) Contract.fail(503, 'company_role_receipt_unavailable');
      const table = action.startsWith('role-') ? 'identity_company_roles' : 'identity_company_role_grants';
      const row = (await client.query('SELECT * FROM ' + table + ' WHERE id=$1 AND tenant_id=$2', [id,proof.tenant.id])).rows[0];
      return { schemaVersion:1,actorUserId:user.identity_authorization.userId,tenantId:proof.tenant.id,eventId,action, ...(action.startsWith('role-') ? {role:role(row)} : {grant:grant({...row,definition_current:true,effective:!row.revoked_at,expired:false})}) };
    }, { actor:user.sub }, Authority.FRESH).catch(error);
  }
  async createGroup(values, user, bearer) {
    values=Contract.group(values);const decision=Contract.decision({reason:values.reason,confirm:values.confirm}); user=structuredClone(user); const commands=this.commands(user);
    return commands.run(user,bearer,async client=>{
      const proof=await Authority.managerProof(client,user);await Authority.receiving(client);
      const creator=new DirectoryCreator({isAvailable:()=>true,transaction:callback=>callback(client)},{issuer:user.iss,revalidate:async(authorization,original)=>{await commands.revalidate(original,authorization);return proof.tenant;}});
      const collection=await creator.group({name:values.name,description:values.description},user,bearer);
      const eventId=(await client.query('SELECT identity_company_role_change($1::jsonb) AS id',[JSON.stringify({action:'group-protect',id:collection.id,eventId:randomUUID(),actor:proof,values:decision})])).rows[0]?.id;
      const receipt=(await client.query("SELECT event.id FROM identity_company_role_events event JOIN identity_company_role_outbox outbox USING(id) WHERE event.id=$1 AND event.resource_id=$2 AND event.tenant_id=$3 AND event.transaction_id=txid_current() AND outbox.status='pending'",[eventId,collection.id,proof.tenant.id])).rows;
      if(receipt.length!==1)Contract.fail(503,'role_group_receipt_unavailable');
      return {schemaVersion:1,actorUserId:user.identity_authorization.userId,tenantId:proof.tenant.id,eventId,group:{id:collection.id,name:collection.name,revision:collection.revision,roleAssignable:true}};
    },{actor:user.sub},Authority.FRESH).catch(error);
  }
  create(values,user,bearer) { return this.change('role-create',randomUUID(),values,null,user,bearer); }
  update(id,values,expected,user,bearer) { Contract.identifier(id); return this.change('role-update',id,values,expected,user,bearer); }
  assign(id,values,expected,user,bearer) { Contract.identifier(id); return this.change('grant-create',randomUUID(),values,expected,user,bearer,id); }
  revoke(id,values,expected,user,bearer) { Contract.identifier(id); return this.change('grant-revoke',id,values,expected,user,bearer); }
}
module.exports = { CompanyRoles, role, grant };
