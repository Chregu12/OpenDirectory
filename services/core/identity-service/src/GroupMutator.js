'use strict';

const crypto = require('crypto');
const {validUuid,validContext,validRevision,sameContext}=require('../../../../packages/identity-authorization-contract');
const {sameTenantContext}=require('../../../../packages/tenant-authorization-contract');
const {createTenantStateClient}=require('../../../../packages/oidc-tenant-state');
const {acceptsRoleAuthentication}=require('../../../../packages/role-authentication-contract');
const {AuthorizationState}=require('./AuthorizationState');
const {DirectoryReader}=require('./DirectoryReader');
const {GroupMembershipReviews}=require('./GroupMembershipReviews');
const {mayUseDirectory,requireDirectoryPermissions}=require('./DirectoryAuthority');

function reject(status,message){throw Object.assign(new Error(message),{status});}
function identifier(value){if(!validUuid(value))reject(400,'Canonical group or member UUID required');return value.toLowerCase();}
function groupEtag(group){return `"group-${group.id}-${group.revision}"`;}
function validateGroupEtag(value){
 if(value===undefined)reject(428,'An exact If-Match group version is required');
 const match=typeof value==='string'&&/^"group-([a-f0-9-]{36})-([1-9][0-9]{0,18})"$/.exec(value);
 if(!match||match[0].length!==value.length||!validUuid(match[1])||!validRevision(match[2]))reject(400,'One strong group ETag is required');
}
function groupFields(body){
 if(!body||typeof body!=='object'||Array.isArray(body)||!Object.keys(body).length||Object.keys(body).some(field=>!['name','description'].includes(field)))reject(400,'Exact group metadata fields required');
 const values={};
 if(Object.hasOwn(body,'name')){if(typeof body.name!=='string'||!body.name.trim()||body.name.length>255||/[\u0000-\u001f\u007f]/.test(body.name))reject(400,'A bounded group name is required');values.name=body.name.trim();}
 if(Object.hasOwn(body,'description')){if(body.description!==null&&(typeof body.description!=='string'||body.description.length>2000||/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(body.description)))reject(400,'Invalid group description');values.description=body.description?.trim()||null;}
 return values;
}

class GroupMutator{
 constructor(database,{issuer=process.env.OIDC_ISSUER||'http://localhost:3001',revalidate=createTenantStateClient(),revalidateAccess,newOperationId=()=>crypto.randomUUID()}={}){
  this.database=database;this.issuer=issuer;this.revalidate=revalidate;this.revalidateAccess=revalidateAccess;this.newOperationId=newOperationId;
 }
 async mutate(action,groupId,memberId,changes,expected,user,authorization){
  groupId=identifier(groupId);if(memberId!==null)memberId=identifier(memberId);validateGroupEtag(expected);
  const permission={update:'groups.update',delete:'groups.delete','member-add':'groups.members.manage','member-remove':'groups.members.manage'}[action];
  if(!this.database.isAvailable())reject(503,'Canonical group storage required');
  if(!permission||user?.actor_type!=='user'||user.iss!==this.issuer||!validContext(user.identity_authorization)||!mayUseDirectory(user,[permission]))reject(403,'Canonical group mutation operator required');
  const tenant=await this.revalidate(authorization,user);const operation=this.newOperationId();
  if(!validUuid(operation))reject(503,'Group mutation identifier unavailable');const operationId=operation.toLowerCase();
  return this.database.transaction(async client=>{
   const current=(await client.query('SELECT id,version,generation FROM identity_tenants WHERE id=$1 AND enabled FOR SHARE',[tenant.id])).rows[0];
   if(!current||!sameTenantContext(tenant,{id:current.id,version:String(current.version),generation:String(current.generation)}))reject(401,'Tenant authority changed');
   const users=[...new Set([user.identity_authorization.userId.toLowerCase(),...(memberId?[memberId]:[])])].sort();
   const locked=(await client.query("SELECT id FROM users WHERE id=ANY($1::uuid[]) AND identity_tenant_id('user',id)=$2 ORDER BY id FOR UPDATE",[users,tenant.id])).rows;
   if(!locked.some(row=>row.id===user.identity_authorization.userId.toLowerCase()))reject(401,'Original group operator unavailable');
   if(memberId&&!locked.some(row=>row.id===memberId))reject(404,'Group or member not found');
   if(!(await client.query("SELECT id FROM groups WHERE id=$1 AND identity_tenant_id('group',id)=$2 FOR UPDATE",[groupId,tenant.id])).rows.length)reject(404,'Group or member not found');
   const source=await new AuthorizationState({transaction:callback=>callback(client)}).state(user.iss,user.sub);
   if(!source.active||!sameContext(source.context,user.identity_authorization)||!sameTenantContext(source.tenant,tenant)||!acceptsRoleAuthentication(source.authentication,user))reject(401,'Original group operator authority changed');
   await requireDirectoryPermissions(client,user,[permission]);
   await client.query("SET LOCAL statement_timeout = '15s'");
   const before=(await client.query('SELECT identity_directory_group_state(to_jsonb(collection)) AS state FROM groups collection WHERE id=$1',[groupId])).rows[0].state;
   if(groupEtag({id:groupId,revision:before.revision})!==expected)reject(412,'Group changed; reload before retrying');
   const beforeMembers=(await client.query('SELECT to_jsonb(member) AS state FROM group_members member WHERE group_id=$1 ORDER BY membership_id LIMIT 10001',[groupId])).rows.map(row=>row.state);
   if(beforeMembers.length>10000||action==='member-add'&&beforeMembers.length===10000)reject(409,'Group membership boundary exceeded');
   const existing=memberId?beforeMembers.find(member=>member.user_id===memberId):null;
   if(action==='member-add'&&existing)reject(409,'Member already linked; reload the group');
   if(action==='member-remove'&&!existing)reject(404,'Group or member not found');
   const policy=action==='member-add'?(await client.query('SELECT id,version,window_seconds,retired_at,identity_directory_group_policy_owned(id,$2) AS coherent FROM identity_membership_review_policies WHERE group_id=$1 ORDER BY (retired_at IS NULL) DESC,created_at DESC,id LIMIT 1',[groupId,tenant.id])).rows[0]:null;
   if(policy?.retired_at)reject(409,'Governed group requires a replacement membership-review policy');
   if(policy&&!policy.coherent)reject(503,'Group review policy scope unavailable');
   if(policy&&!acceptsRoleAuthentication({required:true,maxAgeSeconds:300},user))reject(428,'Fresh MFA required for governed membership');
   if(!sameTenantContext(tenant,await this.revalidate(authorization,user)))reject(401,'Tenant authority changed');
   const rolesSnapshot=(await client.query('SELECT identity_subject_link_role_state($1) AS state',[user.identity_authorization.userId])).rows[0].state;
   const validUntil=Math.min(user.exp,source.authentication.required?user.auth_time+source.authentication.maxAgeSeconds:user.exp,policy?user.auth_time+300:user.exp);
   if(!Number.isFinite(validUntil)||validUntil*1000<=Date.now())reject(401,'Original group operator assurance expired');
   const member=memberId?{id:action==='member-add'?null:existing.membership_id,userId:memberId,before:existing||null,eligibilityRevision:String((await client.query('SELECT eligibility_revision FROM users WHERE id=$1',[memberId])).rows[0].eligibility_revision)}:null;
   const proof={operationId,issuer:user.iss,subject:user.sub,context:user.identity_authorization,tenant,rolesSnapshot,validUntil,target:{id:groupId,action,before,beforeMembers,expectedValues:action==='delete'?null:{name:before.name,description:before.description??null,...changes},member,governance:policy?{id:policy.id,version:String(policy.version),windowSeconds:policy.window_seconds}:null}};
   await client.query("SELECT set_config('opendirectory.group_mutation',$1,true)",[JSON.stringify(proof)]);
   const bound={isAvailable:()=>true,transaction:callback=>callback(client),query:(...args)=>client.query(...args),write:(sql,values)=>client.query(sql,values)};
   let membershipReview=null;
   if(action==='update')await client.query('UPDATE groups SET name=$2,description=$3 WHERE id=$1',[groupId,proof.target.expectedValues.name,proof.target.expectedValues.description]);
   else if(action==='delete')await client.query('DELETE FROM groups WHERE id=$1',[groupId]);
   else if(action==='member-remove')await client.query('DELETE FROM group_members WHERE group_id=$1 AND membership_id=$2 AND user_id=$3',[groupId,member.id,memberId]);
   else membershipReview=await new GroupMembershipReviews(bound,{revalidate:this.revalidateAccess}).add(groupId,memberId,user,authorization);
   await client.query('SELECT identity_directory_group_finish()');
   const receipt=await client.query(`SELECT id FROM identity_directory_group_events WHERE id=$1 AND tenant_id=$2 AND group_id=$3 AND action=$4
    AND scope_sha256=encode(sha256(convert_to($5::jsonb::text,'UTF8')),'hex')
    AND EXISTS(SELECT 1 FROM identity_directory_group_outbox outbox WHERE outbox.id=identity_directory_group_events.id AND outbox.tenant_id=identity_directory_group_events.tenant_id)`,[operationId,tenant.id,groupId,action,JSON.stringify(proof)]);
   if(receipt.rows.length!==1)reject(503,'Tenant-bound group mutation receipt unavailable');
   const result=action==='delete'?null:(await new DirectoryReader(bound,{issuer:this.issuer,revalidate:this.revalidate}).readGroups(client,tenant.id,groupId))[0];
   if(action!=='delete'&&!result)reject(503,'Group mutation readback unavailable');
   if(!sameTenantContext(tenant,await this.revalidate(authorization,user)))reject(401,'Tenant authority changed');
   return membershipReview?{...result,membershipReview}:result;
  },{actor:user.sub});
 }
 async update(groupId,body,expected,user,authorization){return this.mutate('update',groupId,null,groupFields(body),expected,user,authorization);}
 remove(groupId,expected,user,authorization){return this.mutate('delete',groupId,null,null,expected,user,authorization);}
 async add(groupId,body,expected,user,authorization){if(!body||typeof body!=='object'||Array.isArray(body)||Object.keys(body).length!==1||!Object.hasOwn(body,'userId'))reject(400,'One canonical member userId is required');return this.mutate('member-add',groupId,identifier(body.userId),null,expected,user,authorization);}
 async removeMember(groupId,memberId,expected,user,authorization){return this.mutate('member-remove',groupId,identifier(memberId),null,expected,user,authorization);}
}

module.exports={GroupMutator,groupEtag,validateGroupEtag,groupFields};
