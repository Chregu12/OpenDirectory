'use strict';

const {authority,uuid,fields,reason}=require('./PrivilegedActivation');
const {RoleReviews}=require('./RoleReviews');
const {getIdentityPermissions}=require('./middleware/identityAccess');
const {acceptsRoleAuthentication}=require('../../../../packages/role-authentication-contract');
const {validRevision}=require('../../../../packages/identity-authorization-contract');
const {SOURCE_SCOPE,MAX_SOURCE_GRANT_SECONDS}=require('../../../../packages/group-license-lease-contract');
const {LicenseSourceClients,CLIENT_ID}=require('./LicenseSourceClients');
const {GroupSnapshotStore}=require('./GroupSnapshotStore');
const {authorityTenant}=require('./AuthorityTenant');
const {validTenantContext,sameTenantContext}=require('../../../../packages/tenant-authorization-contract');
const fail=(status,code)=>{throw Object.assign(new Error(code),{status,code});};
const fresh=user=>acceptsRoleAuthentication({required:true,maxAgeSeconds:300},user);
const tag=grant=>`"od-group-source:${grant.id}:${grant.version}"`;
const view=row=>({id:row.id,groupId:row.group_id,issuer:row.issuer,clientId:row.client_id,clientRevision:String(row.client_revision),version:String(row.version),createdBy:row.created_by,
 createdAt:row.created_at.toISOString(),expiresAt:row.expires_at.toISOString(),revokedAt:row.revoked_at?.toISOString()||null,state:row.revoked_at?'revoked':row.expires_at<=row.observed_at?'expired':'configured'});
class GroupSourceGrants {
 constructor(database,options={}){this.database=database;this.identity=new RoleReviews(database,options);this.clients=options.clients||new LicenseSourceClients();this.snapshots=options.snapshots||new GroupSnapshotStore(database);}
 actor(user,write=false){const proof=authority(user);if(!getIdentityPermissions(user).includes('licenses.sources.'+(write?'manage':'read')))fail(403,'source_consent_forbidden');if(write&&(!user.roles?.includes('license-scope-administrator')||typeof user.client_id!=='string'||!CLIENT_ID.test(user.client_id)))fail(403,'explicit_source_administrator_required');if(write&&!fresh(user))fail(428,'fresh_mfa_required');return proof;}
 async live(client,user,authorization,write=true){await this.identity.currentActor(client,user,'licenses.sources.'+(write?'manage':'read'));await this.identity.revalidate(user,authorization);this.actor(user,write);return authorityTenant(client,authority(user),{write});}
 async client(clientId,user,authorization){this.actor(user);if(user.iss!==this.clients.issuer)fail(403,'source_issuer_mismatch');return this.clients.get(clientId,authorization);}
 async list(groupId,user,authorization){this.actor(user);groupId=uuid(groupId);return this.database.transaction(async client=>{const tenant=await this.live(client,user,authorization,false);
  if(!(await client.query("SELECT 1 WHERE identity_tenant_id('group',$1::uuid)=$2::uuid",[groupId,tenant])).rows.length)fail(404,'group_not_found');
  const rows=(await client.query("SELECT *,identity_group_source_now() AS observed_at FROM identity_group_source_grants WHERE group_id=$1 AND issuer=$2 AND identity_tenant_id('group',group_id)=$3 ORDER BY created_at DESC,id LIMIT 101",[groupId,user.iss,tenant])).rows;
  if(await this.live(client,user,authorization,false)!==tenant)fail(401,'authority_actor_changed');return{groupId,grants:rows.slice(0,100).map(view),truncated:rows.length>100};},{readOnly:true});}
 async get(id,user,authorization){this.actor(user);id=uuid(id);return this.database.transaction(async client=>{const tenant=await this.live(client,user,authorization,false);
  const row=(await client.query("SELECT grants.*,identity_group_source_now() AS observed_at FROM identity_group_source_grants grants JOIN identity_tenant_ownership ownership ON ownership.resource_kind='group' AND ownership.resource_id=grants.group_id WHERE grants.id=$1 AND grants.issuer=$2 AND ownership.tenant_id=$3",[id,user.iss,tenant])).rows[0];if(!row)fail(404,'source_consent_not_found');
  if(await this.live(client,user,authorization,false)!==tenant)fail(401,'authority_actor_changed');return view(row);},{readOnly:true});}
 async context(client,user,action,explanation,binding){const proof=authority(user);await client.query("SELECT set_config('opendirectory.group_source_actor',$1,true),set_config('opendirectory.group_source_client',$2,true),set_config('opendirectory.group_source_action',$3,true),set_config('opendirectory.group_source_reason',$4,true)",
  [JSON.stringify({...proof,clientId:user.client_id||null,freshMfa:fresh(user),authTime:user.auth_time,factorRevision:user.mfa_authorization?.revision||null}),binding?JSON.stringify(binding):'',action,explanation]);}
 async create(body,user,authorization){const proof=this.actor(user,true);fields(body,['groupId','clientId','expectedClientRevision','expiresAt','reason','acknowledgeReadScope']);if(Object.keys(body).length!==6||body.acknowledgeReadScope!==true||typeof body.clientId!=='string'||!CLIENT_ID.test(body.clientId)||!validRevision(body.expectedClientRevision)||typeof body.expiresAt!=='string'||!Number.isFinite(Date.parse(body.expiresAt))||new Date(body.expiresAt).toISOString()!==body.expiresAt)fail(400,'exact_source_consent_required');
  const groupId=uuid(body.groupId);const explanation=reason(body.reason);const remaining=Date.parse(body.expiresAt)-Date.now();if(remaining<60000||remaining>MAX_SOURCE_GRANT_SECONDS*1000)fail(400,'bounded_source_consent_required');if(user.iss!==this.clients.issuer||body.clientId===user.client_id)fail(403,'separate_canonical_workload_required');
  return this.database.transaction(async client=>{const tenant=await this.live(client,user,authorization);if(!(await client.query("SELECT id FROM groups WHERE id=$1 AND identity_tenant_id('group',id)=$2 FOR UPDATE",[groupId,tenant])).rows.length)fail(404,'group_not_found');if(await this.live(client,user,authorization)!==tenant)fail(401,'authority_actor_changed');
   const binding=await this.clients.get(body.clientId,authorization);if(binding.revision!==body.expectedClientRevision)fail(412,'source_client_changed');if(!binding.enabled||!binding.canReadGroupSources)fail(409,'dedicated_source_client_unavailable');await this.context(client,user,'create',explanation,binding);
   const row=(await client.query('INSERT INTO identity_group_source_grants(group_id,issuer,client_id,client_revision,created_by,expires_at) VALUES($1,$2,$3,$4,$5,$6) RETURNING *,identity_group_source_now() AS observed_at',[groupId,user.iss,body.clientId,binding.revision,proof.userId,body.expiresAt])).rows[0];
   const confirmed=await this.clients.get(body.clientId,authorization);if(JSON.stringify(binding)!==JSON.stringify(confirmed))fail(409,'source_client_changed');if(await this.live(client,user,authorization)!==tenant)fail(401,'authority_actor_changed');if(!(await client.query('SELECT 1 WHERE $1::timestamptz>identity_group_source_now()',[row.expires_at])).rows.length)fail(409,'source_consent_expired');return view(row);
  },{actor:JSON.stringify(proof)});
 }
 async revoke(id,expected,body,user,authorization){this.actor(user,true);fields(body,['reason','acknowledgeReadScope']);if(Object.keys(body).length!==2||body.acknowledgeReadScope!==true)fail(400,'source_scope_acknowledgement_required');const explanation=reason(body.reason);if(!expected)fail(428,'source_consent_version_required');
  return this.database.transaction(async client=>{const tenant=await this.live(client,user,authorization);const current=(await client.query("SELECT grants.*,identity_group_source_now() AS observed_at FROM identity_group_source_grants grants JOIN identity_tenant_ownership ownership ON ownership.resource_kind='group' AND ownership.resource_id=grants.group_id WHERE grants.id=$1 AND grants.issuer=$2 AND ownership.tenant_id=$3 FOR UPDATE OF grants",[uuid(id),user.iss,tenant])).rows[0];if(!current)fail(404,'source_consent_not_found');if(expected!==tag(view(current)))fail(412,'source_consent_changed');if(current.revoked_at)fail(409,'source_consent_revoked');
   if(await this.live(client,user,authorization)!==tenant)fail(401,'authority_actor_changed');await this.context(client,user,'revoke',explanation);const row=(await client.query('UPDATE identity_group_source_grants SET version=version+1,revoked_at=identity_group_source_now() WHERE id=$1 RETURNING *,identity_group_source_now() AS observed_at',[id])).rows[0];if(await this.live(client,user,authorization)!==tenant)fail(401,'authority_actor_changed');return view(row);
  });
 }
 async snapshot(groupId,user,authorization){
  if(user?.actor_type!=='application'||user.token_use!=='access'||user.iss!==this.clients.issuer||user.client_id!==user.sub||typeof user.client_id!=='string'||!CLIENT_ID.test(user.client_id)||!validRevision(user.client_revision)||user.scope!==SOURCE_SCOPE||JSON.stringify(user.permissions)!==JSON.stringify([SOURCE_SCOPE])||user.roles!==undefined||user.realm_access!==undefined||user.identity_authorization!==undefined)fail(403,'dedicated_source_workload_required');
  groupId=uuid(groupId);let targetTenant;
  const authorize=async client=>{await this.identity.revalidate(user,authorization);const row=(await client.query("SELECT grants.*,tenant.id AS target_tenant_id,tenant.version AS target_tenant_version,tenant.generation AS target_tenant_generation,tenant.enabled AS target_tenant_enabled FROM identity_group_source_grants grants JOIN identity_tenants tenant ON tenant.id=identity_tenant_id('group',grants.group_id) AND tenant.id=identity_tenant_id('user',grants.created_by) WHERE grants.group_id=$1 AND grants.issuer=$2 AND grants.client_id=$3 AND grants.client_revision=$4 AND grants.revoked_at IS NULL AND grants.expires_at>identity_group_source_now() FOR SHARE OF grants",[groupId,user.iss,user.client_id,user.client_revision])).rows[0];if(!row)fail(403,'current_group_source_consent_required');
   const tenant={id:row.target_tenant_id,version:String(row.target_tenant_version),generation:String(row.target_tenant_generation)};if(!validTenantContext(tenant)||typeof row.target_tenant_enabled!=='boolean')fail(503,'source_target_tenant_unavailable');
   if(targetTenant&&(!sameTenantContext(targetTenant.context,tenant)||targetTenant.enabled!==row.target_tenant_enabled))fail(409,'source_target_tenant_changed');targetTenant={context:tenant,enabled:row.target_tenant_enabled};
   return{grantId:row.id,version:String(row.version),issuer:row.issuer,clientId:row.client_id,clientRevision:String(row.client_revision),expiresAt:row.expires_at.toISOString()};};
  return this.snapshots.snapshot(groupId,null,{authorize});
 }
}
module.exports={GroupSourceGrants,tag};
