'use strict';

const crypto=require('crypto');
const {validUuid,validContext,sameContext}=require('../../../../packages/identity-authorization-contract');
const {sameTenantContext}=require('../../../../packages/tenant-authorization-contract');
const {createTenantStateClient}=require('../../../../packages/oidc-tenant-state');
const {acceptsRoleAuthentication}=require('../../../../packages/role-authentication-contract');
const {AuthorizationState}=require('./AuthorizationState');
const {DirectoryUsers,userFromRow,userEtag,userFields,validateUserEtag}=require('./DirectoryUsers');
const {mayUseDirectory,requireDirectoryPermissions}=require('./DirectoryAuthority');
function reject(status,message){throw Object.assign(new Error(message),{status});}
function profile(row){return{username:row.username,email:row.email,displayName:row.display_name??null,department:row.department??null,title:row.title??null,enabled:row.enabled};}

class UserMutator{
 constructor(database,{issuer=process.env.OIDC_ISSUER||'http://localhost:3001',revalidate=createTenantStateClient(),newOperationId=()=>crypto.randomUUID()}={}){
  this.database=database;this.issuer=issuer;this.revalidate=revalidate;this.newOperationId=newOperationId;
 }
 async mutate(action,userId,changes,expected,user,authorization){
  if(!validUuid(userId))reject(400,'Canonical user UUID required');const targetId=userId.toLowerCase();
  if(action!=='invalidate')validateUserEtag(expected);
  const permissions={update:['users.update',...(Object.hasOwn(changes||{},'enabled')?['users.status.manage']:[])],delete:['users.delete'],invalidate:['users.sessions.invalidate']}[action];
  if(!this.database.isAvailable())reject(503,'Canonical directory storage required');
  if(!permissions||user?.actor_type!=='user'||user.iss!==this.issuer||!validContext(user.identity_authorization)||!mayUseDirectory(user,permissions))reject(403,'Canonical user mutation operator required');
  const tenant=await this.revalidate(authorization,user);const operationId=this.newOperationId();if(!validUuid(operationId))reject(503,'Mutation identifier unavailable');
  return this.database.transaction(async client=>{
   const current=(await client.query('SELECT id,version,generation FROM identity_tenants WHERE id=$1 AND enabled FOR SHARE',[tenant.id])).rows[0];
   if(!current||!sameTenantContext(tenant,{id:current.id,version:String(current.version),generation:String(current.generation)}))reject(401,'Tenant authority changed');
   const ids=[...new Set([user.identity_authorization.userId.toLowerCase(),targetId])].sort();
   const locked=(await client.query("SELECT id FROM users WHERE id=ANY($1::uuid[]) AND identity_tenant_id('user',id)=$2 ORDER BY id FOR UPDATE",[ids,tenant.id])).rows;
   if(!locked.some(row=>row.id===user.identity_authorization.userId.toLowerCase()))reject(401,'Original operator unavailable');
   if(!locked.some(row=>row.id===targetId))reject(404,'User not found');
   const source=await new AuthorizationState({transaction:callback=>callback(client)}).state(user.iss,user.sub);
   if(!source.active||!sameContext(source.context,user.identity_authorization)||!sameTenantContext(source.tenant,tenant)||!acceptsRoleAuthentication(source.authentication,user))reject(401,'Original operator authority changed');
   await requireDirectoryPermissions(client,user,permissions);
   await client.query("SET LOCAL statement_timeout = '15s'");
   const before=(await client.query("SELECT identity_directory_user_state(to_jsonb(account)) AS state FROM users account WHERE account.id=$1 AND identity_tenant_id('user',account.id)=$2",[targetId,tenant.id])).rows[0]?.state;
   if(!before)reject(404,'User not found');
   if(action!=='invalidate'&&userEtag(userFromRow(before))!==expected)reject(412,'User changed; reload before retrying');
   if(action==='delete'&&(await client.query('SELECT id FROM identity_directory_ou_members WHERE user_id=$1 LIMIT 1',[targetId])).rows.length)reject(409,'user_has_organization_memberships');
   if(!sameTenantContext(tenant,await this.revalidate(authorization,user)))reject(401,'Tenant authority changed');
   const expectedValues=action==='delete'?null:{...profile(before),...(changes||{})};
   const rolesSnapshot=(await client.query('SELECT identity_subject_link_role_state($1) AS state',[user.identity_authorization.userId])).rows[0].state;
   const validUntil=Math.min(user.exp,source.authentication.required?user.auth_time+source.authentication.maxAgeSeconds:user.exp);
   if(!Number.isFinite(validUntil)||validUntil*1000<=Date.now())reject(401,'Original operator assurance expired');
   const proof={operationId:operationId.toLowerCase(),issuer:user.iss,subject:user.sub,context:user.identity_authorization,tenant,rolesSnapshot,validUntil,target:{id:targetId,action,before,expectedValues}};
   await client.query("SELECT set_config('opendirectory.user_mutation',$1,true)",[JSON.stringify(proof)]);
   const bound={isAvailable:()=>true,transaction:callback=>callback(client),write:(sql,values)=>client.query(sql,values)};
   const result=action==='update'?await new DirectoryUsers(bound).update(targetId,changes,expected,user.sub):action==='delete'?await new DirectoryUsers(bound).remove(targetId,expected,user.sub):await new AuthorizationState(bound).invalidate(targetId,user.sub);
   const receipt=await client.query(`SELECT id FROM identity_directory_user_events WHERE id=$1 AND tenant_id=$2 AND user_id=$3 AND action=$4
    AND scope_sha256=encode(sha256(convert_to($5::jsonb::text,'UTF8')),'hex')
    AND EXISTS(SELECT 1 FROM identity_directory_user_outbox outbox WHERE outbox.id=identity_directory_user_events.id AND outbox.tenant_id=identity_directory_user_events.tenant_id)`,[proof.operationId,tenant.id,targetId,action,JSON.stringify(proof)]);
   if(receipt.rows.length!==1)reject(503,'Tenant-bound user mutation receipt unavailable');
   if(!sameTenantContext(tenant,await this.revalidate(authorization,user)))reject(401,'Tenant authority changed');
   return result;
  },{actor:user.sub});
 }
 async update(userId,body,expected,user,authorization){return this.mutate('update',userId,userFields(body),expected,user,authorization);}
 remove(userId,expected,user,authorization){return this.mutate('delete',userId,null,expected,user,authorization);}
 invalidate(userId,user,authorization){return this.mutate('invalidate',userId,null,undefined,user,authorization);}
}
module.exports={UserMutator};
