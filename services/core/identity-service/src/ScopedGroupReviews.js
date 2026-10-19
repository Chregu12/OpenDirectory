'use strict';

const crypto=require('crypto');
const {validUuid,sameContext}=require('../../../../packages/identity-authorization-contract');
const {sameTenantContext}=require('../../../../packages/tenant-authorization-contract');
const {acceptsRoleAuthentication}=require('../../../../packages/role-authentication-contract');
const {createTenantStateClient}=require('../../../../packages/oidc-tenant-state');
const {GroupMembershipReviews}=require('./GroupMembershipReviews');
const {DirectoryReader}=require('./DirectoryReader');
const {AuthorizationState}=require('./AuthorizationState');
const {authority,uuid,fields,reason}=require('./PrivilegedActivation');
function fail(status,code){throw Object.assign(new Error(code),{status,code});}
function bound(client){return{isAvailable:()=>true,query:(...args)=>client.query(...args),transaction:callback=>callback(client),write:(sql,values)=>client.query(sql,values)};}

class ScopedGroupReviews{
 constructor(database,{issuer=process.env.OIDC_ISSUER||'http://localhost:3001',revalidate=createTenantStateClient(),revalidateAccess,newOperationId=()=>crypto.randomUUID()}={}){
  this.database=database;this.issuer=issuer;this.revalidate=revalidate;this.revalidateAccess=revalidateAccess;this.newOperationId=newOperationId;
  this.reader=new DirectoryReader(database,{issuer,revalidate});
 }
 raw(database=this.database,tenantId=null){return new GroupMembershipReviews(database,{tenantId,revalidate:this.revalidateAccess});}
 policy(groupId,user,authorization){groupId=uuid(groupId);this.raw().actor(user,'policies.read');return this.reader.read(['groups.reviews.policies.read'],user,authorization,(client,tenant)=>this.raw(bound(client),tenant).policy(groupId,user));}
 get(id,user,authorization){id=uuid(id);authority(user);return this.reader.read([],user,authorization,(client,tenant)=>this.raw(bound(client),tenant).get(id,user,client));}
 list(own,user,authorization){authority(user);if(!own)this.raw().actor(user,'assigned.read');return this.reader.read(own?[]:['groups.reviews.assigned.read'],user,authorization,(client,tenant)=>this.raw(bound(client),tenant).list(own,user));}
 async write(action,id,expected,body,user,authorization){
  const actor=authority(user);this.raw().actor(user,action==='create'||action==='retire'?'policies.manage':'decide',true);
  if(user.iss!==this.issuer)fail(403,'canonical_group_review_issuer_required');
  if(!this.database.isAvailable())fail(503,'canonical_group_review_storage_required');
  if(action==='create'){
   fields(body,['groupId','intervalSeconds','windowSeconds','reviewerUserIds','reason','acknowledgeEffects']);id=uuid(body.groupId);
   if(Object.keys(body).length!==6||body.acknowledgeEffects!==true||!Number.isInteger(body.intervalSeconds)||body.intervalSeconds<60||body.intervalSeconds>2592000||!Number.isInteger(body.windowSeconds)||body.windowSeconds<60||body.windowSeconds>Math.min(604800,body.intervalSeconds)||!Array.isArray(body.reviewerUserIds)||!body.reviewerUserIds.length||body.reviewerUserIds.length>10||new Set(body.reviewerUserIds).size!==body.reviewerUserIds.length||body.reviewerUserIds.includes(actor.userId))fail(400,'independent_bounded_membership_policy_required');body.reviewerUserIds.forEach(value=>{if(uuid(value)!==value)fail(400,'canonical_uuid_required');});
  }else{id=uuid(id);fields(body,action==='retire'?['reason','acknowledgeEffects']:['decision','reason','acknowledgeScope']);if(action==='retire'?(Object.keys(body).length!==2||body.acknowledgeEffects!==true):(Object.keys(body).length!==3||!['retain','deny'].includes(action)||body.decision!==action||body.acknowledgeScope!==true))fail(400,'membership_review_intent_required');if(!expected)fail(428,'membership_review_version_required');}
  const explanation=reason(body.reason);const tenant=await this.revalidate(authorization,user);const operation=this.newOperationId();if(!validUuid(operation))fail(503,'group_review_operation_unavailable');
  return this.database.transaction(async client=>{
   const parent=(await client.query('SELECT id,version,generation FROM identity_tenants WHERE id=$1 AND enabled FOR SHARE',[tenant.id])).rows[0];
   if(!parent||!sameTenantContext(tenant,{id:parent.id,version:String(parent.version),generation:String(parent.generation)}))fail(401,'tenant_authority_changed');
   let groupId=id;let recipient=null;
   if(action==='retire'){
    const peek=(await client.query("SELECT group_id FROM identity_membership_review_policies WHERE id=$1 AND issuer=$2 AND identity_tenant_id('group',group_id)=$3 AND identity_directory_group_policy_owned(id,$3)",[id,user.iss,tenant.id])).rows[0];if(!peek)fail(404,'membership_policy_not_found');groupId=peek.group_id;
   }else if(action!=='create'){
    const peek=(await client.query(`SELECT origin.group_id,origin.user_id FROM identity_membership_review_leases lease JOIN identity_membership_origins origin ON origin.membership_id=lease.membership_id JOIN identity_membership_review_policies policy ON policy.id=lease.policy_id
     WHERE lease.id=$1 AND policy.issuer=$2 AND identity_tenant_id('group',origin.group_id)=$3 AND identity_tenant_id('user',origin.user_id)=$3
     AND (origin.created_by IS NULL OR identity_tenant_id('user',origin.created_by)=$3) AND identity_directory_group_policy_owned(policy.id,$3)`,[id,user.iss,tenant.id])).rows[0];if(!peek)fail(404,'membership_review_not_found');groupId=peek.group_id;recipient=peek.user_id;
   }
   if(!(await client.query("SELECT id FROM groups WHERE id=$1 AND identity_tenant_id('group',id)=$2",[groupId,tenant.id])).rows.length)fail(404,'group_not_found');
   let inventory=[];
   if(action==='create'){
    inventory=(await client.query(`SELECT member.membership_id,member.user_id,account.id AS owned_user_id,
     origin.membership_id IS NOT NULL AND origin.group_id=member.group_id AND origin.user_id::text=member.user_id
      AND (origin.created_by IS NULL OR identity_tenant_id('user',origin.created_by)=$2) AS coherent_origin
     FROM group_members member LEFT JOIN users account ON account.id::text=member.user_id AND identity_tenant_id('user',account.id)=$2
     LEFT JOIN identity_membership_origins origin ON origin.membership_id=member.membership_id WHERE member.group_id=$1 ORDER BY member.membership_id LIMIT 1001`,[groupId,tenant.id])).rows;
    if(inventory.length>1000||inventory.some(member=>!member.owned_user_id||!member.coherent_origin))fail(409,'membership_review_inventory_scope_unavailable');
   }
   const reviewers=action==='create'?body.reviewerUserIds.map(uuid):[];const users=[...new Set([actor.userId,...inventory.map(member=>member.owned_user_id),...reviewers,...(recipient?[recipient]:[])])].sort();
   const locked=(await client.query("SELECT id FROM users WHERE id=ANY($1::uuid[]) AND identity_tenant_id('user',id)=$2 ORDER BY id FOR UPDATE",[users,tenant.id])).rows;
   if(!locked.some(row=>row.id===actor.userId))fail(401,'original_group_reviewer_unavailable');if(locked.length!==users.length)fail(404,'membership_reference_not_found');
   if(!(await client.query("SELECT id FROM groups WHERE id=$1 AND identity_tenant_id('group',id)=$2 FOR UPDATE",[groupId,tenant.id])).rows.length)fail(404,'group_not_found');
   const source=await new AuthorizationState({transaction:callback=>callback(client)}).state(user.iss,user.sub);
   if(!source.active||!sameContext(source.context,user.identity_authorization)||!sameTenantContext(source.tenant,tenant)||!acceptsRoleAuthentication(source.authentication,user))fail(401,'original_group_review_authority_changed');
   await client.query("SET LOCAL statement_timeout='15s'");
   const before=(await client.query('SELECT identity_directory_group_review_snapshot($1) AS state',[groupId])).rows[0].state;
   if(before.members.length>10000||before.policies.length>10000||before.leases.length>10000)fail(409,'group_review_snapshot_boundary');
   if(action==='create'&&(before.members.length!==inventory.length||before.members.some(member=>!inventory.some(previous=>previous.membership_id===member.membership_id))))fail(409,'membership_inventory_changed');
   const root=action==='create'?null:(action==='retire'?before.policies:before.leases).find(row=>row.id===id);if(action!=='create'&&!root)fail(404,'membership_review_not_found');
   const validUntil=Math.min(user.exp,user.auth_time+300,source.authentication.required?user.auth_time+source.authentication.maxAgeSeconds:user.exp);
   if(!Number.isFinite(validUntil)||validUntil*1000<=Date.now())fail(401,'original_group_review_assurance_expired');
   const voters=[];
   for(const reviewer of [...new Set(reviewers)].sort()){
    const link=(await client.query('SELECT subject FROM identity_subject_links WHERE issuer=$1 AND user_id=$2',[user.iss,reviewer])).rows[0];if(!link)fail(409,'membership_reviewer_unavailable');
    const state=await new AuthorizationState({transaction:callback=>callback(client)}).state(user.iss,link.subject);
    if(!state.active||!sameTenantContext(state.tenant,tenant)||!state.roles.includes('group-reviewer'))fail(409,'membership_reviewer_unavailable');
    voters.push({issuer:user.iss,subject:link.subject,context:state.context,tenant,validUntil,rolesSnapshot:(await client.query('SELECT identity_subject_link_role_state($1) AS state',[reviewer])).rows[0].state});
   }
   await client.query("SET LOCAL statement_timeout='15s'");
   if(!sameTenantContext(tenant,await this.revalidate(authorization,user)))fail(401,'tenant_authority_changed');
   const proof={operationId:operation.toLowerCase(),issuer:user.iss,subject:user.sub,context:user.identity_authorization,tenant,rolesSnapshot:(await client.query('SELECT identity_subject_link_role_state($1) AS state',[actor.userId])).rows[0].state,
    authTime:user.auth_time,factorRevision:user.mfa_authorization.revision,validUntil,action,groupId,rootId:action==='create'?null:id,before,voters,
    observedAt:(await client.query('SELECT identity_membership_review_now() AS now')).rows[0].now.toISOString(),intent:{...body,reason:explanation,...(action==='create'?{reviewerUserIds:[...reviewers].sort()}:{}),expected:expected||null}};
   await client.query("SELECT set_config('opendirectory.group_review',$1,true)",[JSON.stringify(proof)]);
   const store=this.raw(bound(client),tenant.id);const result=action==='create'?await store.create(body,user,authorization):action==='retire'?await store.retire(id,expected,body,user,authorization):await store.decide(id,expected,body,user,authorization);
   await client.query('SELECT identity_directory_group_review_finish()');
   const receipt=await client.query(`SELECT id FROM identity_directory_group_review_events WHERE id=$1 AND tenant_id=$2 AND group_id=$3 AND root_id=$4 AND action=$5 AND scope_sha256=encode(sha256(convert_to($6::jsonb::text,'UTF8')),'hex')
    AND EXISTS(SELECT 1 FROM identity_directory_group_review_outbox outbox WHERE outbox.id=identity_directory_group_review_events.id AND outbox.tenant_id=identity_directory_group_review_events.tenant_id)`,[proof.operationId,tenant.id,groupId,result.id,action,JSON.stringify(proof)]);
   if(receipt.rows.length!==1)fail(503,'group_review_receipt_unavailable');if(!sameTenantContext(tenant,await this.revalidate(authorization,user)))fail(401,'tenant_authority_changed');return result;
  },{actor:user.sub});
 }
 create(body,user,authorization){return this.write('create',null,null,body,user,authorization);}
 retire(id,expected,body,user,authorization){return this.write('retire',id,expected,body,user,authorization);}
 decide(id,expected,body,user,authorization){return this.write(body?.decision,id,expected,body,user,authorization);}
}
module.exports={ScopedGroupReviews};
