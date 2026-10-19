'use strict';

const {validContext,sameContext,validUuid,validRevision}=require('../../../../packages/identity-authorization-contract');
const {sameTenantContext,validTenantContext}=require('../../../../packages/tenant-authorization-contract');
const {acceptsRoleAuthentication}=require('../../../../packages/role-authentication-contract');
const {createTenantStateClient}=require('../../../../packages/oidc-tenant-state');
const {createAccessStateClient}=require('../../../../packages/oidc-access-state');
const {AuthorizationState}=require('./AuthorizationState');
const {getIdentityPermissions}=require('./middleware/identityAccess');
const {CLIENT_ID}=require('./LicenseSourceClients');
function fail(status,message){throw Object.assign(new Error(message),{status});}
class SnapshotBoundary{
  constructor(database,{issuer=process.env.OIDC_ISSUER || 'http://localhost:3001',revalidateTenant=createTenantStateClient(),revalidateAccess=createAccessStateClient()}={}){
    this.database=database;this.issuer=issuer;this.revalidateTenant=revalidateTenant;this.revalidateAccess=revalidateAccess;
  }
  scoped(frame){return{transaction:(operation)=>this.run(frame,operation)};}
  async target(client,kind,id,tenant){
    const owner=(await client.query('SELECT identity_tenant_id($1,$2::uuid) AS tenant_id',[kind,id])).rows[0]?.tenant_id;
    if(owner!==tenant)fail(404,'Snapshot target not found');
  }
  async actor(client,frame,tenant){
    const user=frame.user;const state=await new AuthorizationState({transaction:operation=>operation(client)}).state(user.iss,user.sub);
    if(!state.active || !sameContext(state.context,user.identity_authorization) || !sameTenantContext(state.tenant,tenant) || !acceptsRoleAuthentication(state.authentication,user))fail(401,'Original snapshot authority changed');
    if(!(frame.self && frame.kind==='user' && frame.id===state.context.userId) && !getIdentityPermissions({actor_type:'user',roles:state.roles}).includes(frame.permission))fail(403,'Canonical snapshot duty required');
    return state.authentication;
  }
  async workloadState(client,user){
    const row=(await client.query('SELECT binding.*,identity_license_user_source_valid(binding) AS valid FROM identity_license_user_sources binding WHERE issuer=$1 AND client_id=$2',[user.iss,user.client_id])).rows[0];
    if(!row || !row.enabled)fail(403,'Explicit tenant-bound user source required');
    if(row.valid!==true || !validUuid(row.id) || !validUuid(row.event_id) || !validUuid(row.tenant_id) || !validRevision(String(row.version)) || !validRevision(String(row.client_revision)))fail(503,'Retained user-source evidence unavailable');
    if(String(row.client_revision)!==user.client_revision)fail(403,'User-source client generation changed');
    const current=(await client.query('SELECT id,version,generation,enabled FROM identity_tenants WHERE id=$1',[row.tenant_id])).rows[0];
    const tenant=current?{id:current.id,version:String(current.version),generation:String(current.generation)}:null;
    if(!validTenantContext(tenant) || typeof current.enabled!=='boolean')fail(503,'Canonical user-source tenant unavailable');
    return{tenant,tenantEnabled:current.enabled,id:row.id,version:String(row.version),eventId:row.event_id,clientRevision:String(row.client_revision)};
  }
  async workload(frame,operation){
    const user=frame.user;
    if(!frame.workload || frame.kind!=='user' || frame.permission!=='licenses.users.read' || user.token_use!=='access' || user.sub!==user.client_id || typeof user.client_id!=='string' || !CLIENT_ID.test(user.client_id)
      || !validRevision(user.client_revision) || user.scope!=='licenses.users.read' || JSON.stringify(user.permissions)!==JSON.stringify(['licenses.users.read'])
      || user.roles!==undefined || user.realm_access!==undefined || user.identity_authorization!==undefined)fail(403,'Dedicated tenant-bound user source required');
    await this.revalidateAccess(frame.authorization,user);const original=await this.workloadState(this.database,user);
    const result=await this.database.transaction(async client=>{
      if(JSON.stringify(await this.workloadState(client,user))!==JSON.stringify(original))fail(401,'User-source binding changed');
      await this.target(client,frame.kind,frame.id,original.tenant.id);const value=await operation(client);await this.revalidateAccess(frame.authorization,user);return value;
    },{readOnly:true});
    if(JSON.stringify(await this.workloadState(this.database,user))!==JSON.stringify(original))fail(401,'User-source binding changed');
    await this.revalidateAccess(frame.authorization,user);if(user.exp*1000<=Date.now())fail(401,'Original user-source deadline expired');return result;
  }
  async run(frame,operation){
    const user=frame.user;
    if(!this.database.isAvailable())fail(503,'Canonical snapshot storage required');
    if(!['user','group'].includes(frame.kind) || !validUuid(frame.id) || frame.id!==frame.id.toLowerCase())fail(400,'Canonical snapshot target required');
    if(user?.iss!==this.issuer || typeof frame.authorization!=='string' || frame.authorization.length>16384 || !/^Bearer [A-Za-z0-9._~-]+$/.test(frame.authorization) || !Number.isFinite(user.exp))fail(403,'Original snapshot bearer required');
    if(user.exp*1000<=Date.now())fail(401,'Original snapshot deadline expired');
    if(user.actor_type==='application')return this.workload(frame,operation);
    if(user.actor_type!=='user' || !validContext(user.identity_authorization))fail(403,'Canonical snapshot human required');
    const tenant=await this.revalidateTenant(frame.authorization,user);let authentication;
    const check=async()=>{if(!sameTenantContext(tenant,await this.revalidateTenant(frame.authorization,user)) || !acceptsRoleAuthentication(authentication,user) || user.exp*1000<=Date.now())fail(401,'Original snapshot authority changed');};
    const result=await this.database.transaction(async client=>{
      authentication=await this.actor(client,frame,tenant);await this.target(client,frame.kind,frame.id,tenant.id);
      const value=await operation(client);await this.actor(client,frame,tenant);await check();return value;
    },{readOnly:frame.write!==true});await check();return result;
  }
}
module.exports={SnapshotBoundary};
