'use strict';
const {randomUUID,randomBytes}=require('node:crypto');const {isDeepStrictEqual}=require('node:util');const bcrypt=require('bcryptjs');
const contract=require('../../../../packages/employee-invitation-contract');const {sameTenantContext}=require('../../../../packages/tenant-authorization-contract');
const {sameContext}=require('../../../../packages/identity-authorization-contract');
const {EmployeeInvitationAuthorityClient}=require('./EmployeeInvitationAuthorityClient');
const PostgresUserRepository=require('./infrastructure/repositories/PostgresUserRepository');const UserAggregate=require('./domain/aggregates/UserAggregate');
const PasswordPolicyEnforcer=require('./policies/PasswordPolicyEnforcer');
const iso=value=>new Date(value).toISOString();
const view=row=>({id:row.id,tenantId:row.tenant.id,userId:row.target_id,loginName:row.login_name,organizationName:row.grant_source.organizationName,
 status:row.status,revision:String(row.revision),createdAt:iso(row.created_at),expiresAt:iso(row.expires_at),credentialCreated:row.credential_event_id!==null,identityConfirmed:row.identity_receipt!==null});
function witness(row){return{id:row.id,tenant:row.tenant,subjectId:row.subject_id,request:row.request,source:row.grant_source,createdAt:iso(row.created_at),expiresAt:iso(row.expires_at),creationEventId:row.creation_event_id,
 credential:row.credential_event_id?{eventId:row.credential_event_id,revision:String(row.credential_revision)}:null};}
function proof(operation,input,claims,owner){
 if(!claims||claims.actor_type!=='workload'||claims.sub!=='oauth-provider'||claims.aud!==contract.AUDIENCE||claims.token_use!==contract.PURPOSE||claims.scope!=='employees.invitations.'+operation
  ||claims.body_sha256!==contract.digest(input)||claims.owner_sha256!==(owner?contract.digest(owner):null)||!Number.isSafeInteger(claims.exp)||!Number.isSafeInteger(claims.iat)||claims.iat>Math.floor(Date.now()/1000)||claims.exp<=claims.iat||claims.exp*1000<=Date.now()||claims.exp-claims.iat>30)contract.fail(401,'original_employee_invitation_proof_required');
 contract.identifier(claims.jti);return{issuer:claims.iss,subject:claims.sub,expiresAt:claims.exp,tokenId:claims.jti};
}
class EmployeeInvitations{
 constructor(database,{authority=new EmployeeInvitationAuthorityClient(),observe,accepted}={}){Object.assign(this,{database,authority,observe,accepted});}
 async transaction(operation,{proof:original,ownerSource,verify}={}){
  if(!this.database.isAvailable())contract.fail(503,'employee_invitation_storage_unavailable');const client=await this.database.getClient();
  try{await client.query('BEGIN');await client.query("SET LOCAL timezone='UTC';SET LOCAL statement_timeout='10s';SET LOCAL lock_timeout='2s'");await client.query('SELECT auth_employee_invitation_receiving()');
   const result=await operation(client,async(target,actualAction,extra={})=>{
    const validUntil=Math.min(original.expiresAt,ownerSource?.validUntil??original.expiresAt,extra.validUntil??original.expiresAt);
    const scope={...extra,invitationId:target,action:actualAction,proof:original,ownerSource:ownerSource||null,eventId:randomUUID(),validUntil};
    await client.query("SELECT set_config('opendirectory.employee_invitation',$1,true)",[JSON.stringify(scope)]);return scope;
   });
   if(verify)await verify();await client.query('COMMIT');return result;
  }catch(error){await client.query('ROLLBACK').catch(()=>{});if(error.status)throw error;contract.fail(error.code==='23505'?409:503,error.code==='23505'?'employee_invitation_conflict':'employee_invitation_outcome_unconfirmed');}
  finally{client.release();}
 }
 async row(client,id,tenant=null,lock=false){
  contract.identifier(id);const row=(await client.query(`SELECT invitation.*,auth_employee_invitation_valid(id) AS valid FROM auth_employee_invitations invitation WHERE id=$1${tenant?' AND tenant->>\'id\'=$2':''}${lock?' FOR UPDATE':''}`,[id,...(tenant?[tenant]:[])])).rows[0];
  if(!row)contract.fail(404,'employee_invitation_not_found');if(row.valid!==true)contract.fail(503,'employee_invitation_evidence_unavailable');return row;
 }
 async owner(operation,input,claims,authorization,run){
  const original=proof(operation,input,claims,authorization);const source=await this.authority.owner(authorization);if(source.issuer!==original.issuer)contract.fail(401,'employee_invitation_issuer_changed');
  const verify=async()=>{if(!isDeepStrictEqual(source,await this.authority.owner(authorization)))contract.fail(412,'employee_invitation_owner_changed');};
  const result=await this.transaction((client,admit)=>run(client,source,original,admit),{proof:original,ownerSource:source,verify});await verify();return{schemaVersion:1,employeeInvitationProtocol:1,actorUserId:source.actorUserId,tenant:source.tenant,...result};
 }
 async create(raw,claims,authorization){
  const input=contract.createInput(raw);const original=proof('create',raw,claims,authorization);let source=await this.authority.owner(authorization);
  if(source.issuer!==original.issuer)contract.fail(401,'employee_invitation_issuer_changed');
  let verify=async()=>{if(!isDeepStrictEqual(source,await this.authority.owner(authorization,source.target?input.userId:null)))contract.fail(412,'employee_invitation_owner_changed');};
  const result=await this.transaction(async(client,admit)=>{
   await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',['employee-invitation:'+source.tenant.id]);
   const previous=(await client.query("SELECT * FROM auth_employee_invitations WHERE id=$1 AND tenant->>'id'=$2 FOR UPDATE",[input.id,source.tenant.id])).rows[0];
   if(previous){const row=await this.row(client,input.id,source.tenant.id);if(!isDeepStrictEqual(row.request,input))contract.fail(409,'original_employee_invitation_request_changed');return{invitation:view(row),created:false,invitationToken:null};}
   const recipient=await this.authority.owner(authorization,input.userId);
   if(!sameContext(source.context,recipient.context)||!sameTenantContext(source.tenant,recipient.tenant))contract.fail(412,'employee_invitation_owner_changed');source=recipient;
   if(!source.target||source.target.id!==input.userId||source.target.revision!==input.userRevision)contract.fail(412,'employee_invitation_recipient_changed');
   if(source.target.enabled||!source.target.unlinked||!source.target.ordinary)contract.fail(409,'disabled_unlinked_ordinary_employee_required');
   if(Number((await client.query("SELECT count(*) AS n FROM auth_employee_invitations WHERE tenant->>'id'=$1 AND status IN('pending','credential_pending') AND expires_at>clock_timestamp()",[source.tenant.id])).rows[0].n)>=1000)contract.fail(429,'employee_invitation_capacity_reached');
   const token=input.id+'.'+randomBytes(32).toString('base64url');const parsed=contract.parseToken(token);
   const scope={invitationId:input.id,action:'created',proof:original,ownerSource:source,eventId:randomUUID(),validUntil:Math.min(original.expiresAt,source.validUntil)};
   await client.query("SELECT set_config('opendirectory.employee_invitation',$1,true)",[JSON.stringify(scope)]);
   await client.query(`WITH original_time AS(SELECT clock_timestamp() AS value)
    INSERT INTO auth_employee_invitations(id,tenant,target_id,subject_id,login_name,token_hash,request,grant_source,status,created_at,expires_at,creation_event_id,event_id)
    SELECT $1,$2,$3,$4,$5,$6,$7,$8,'pending',value,value+$9*interval '1 hour',$10,$10 FROM original_time`,[input.id,source.tenant,input.userId,randomUUID(),input.loginName,parsed.tokenHash,input,source,input.durationHours,scope.eventId]);
   return{invitation:view(await this.row(client,input.id,source.tenant.id)),created:true,invitationToken:token};
  },{proof:original,verify:()=>verify()});
  await verify();return{schemaVersion:1,employeeInvitationProtocol:1,actorUserId:source.actorUserId,tenant:source.tenant,...result};
 }
 async list(input,claims,authorization){
  contract.exact(input,['page']);if(!Number.isSafeInteger(input.page)||input.page<1||input.page>1000000)contract.fail(400,'positive_employee_invitation_page_required');
  return this.owner('list',input,claims,authorization,async(client,source)=>{const rows=(await client.query("SELECT invitation.*,auth_employee_invitation_valid(id) AS valid FROM auth_employee_invitations invitation WHERE tenant->>'id'=$1 ORDER BY created_at DESC,id LIMIT 26 OFFSET $2",[source.tenant.id,(input.page-1)*25])).rows;
   if(rows.some(row=>!row.valid))contract.fail(503,'employee_invitation_evidence_unavailable');return{page:input.page,hasMore:rows.length>25,invitations:rows.slice(0,25).map(view)};});
 }
 async get(input,claims,authorization){contract.exact(input,['id']);return this.owner('get',input,claims,authorization,async(client,source)=>({invitation:view(await this.row(client,input.id,source.tenant.id))}));}
 async inspect(input,claims){
  contract.exact(input,['token']);const original=proof('inspect',input,claims);const parsed=contract.parseToken(input.token);
  return this.transaction(async client=>{const row=await this.row(client,parsed.id);if(row.grant_source.issuer!==original.issuer||row.token_hash!==parsed.tokenHash||row.status==='revoked'||row.status==='pending'&&new Date(row.expires_at).getTime()<=Date.now())contract.fail(401,'invalid_employee_invitation');
   return{schemaVersion:1,employeeInvitationProtocol:1,invitation:view(row),witness:witness(row)};},{proof:original});
 }
 async credential(input,claims){
  contract.exact(input,['token','password','observationAssertion']);const original=proof('credential',input,claims);contract.password(input.password);const parsed=contract.parseToken(input.token);
  if(typeof input.observationAssertion!=='string'||input.observationAssertion.length>16384||!this.observe)contract.fail(503,'employee_invitation_observer_unavailable');
  return this.transaction(async(client,admit)=>{
   const row=await this.row(client,parsed.id,null,true);if(row.grant_source.issuer!==original.issuer||row.token_hash!==parsed.tokenHash||row.status==='revoked')contract.fail(401,'invalid_employee_invitation');
   const repository=new PostgresUserRepository(client);
   if(row.credential_event_id){const credential=await repository.findById(row.subject_id);if(!credential||!await bcrypt.compare(input.password,credential.passwordHash))contract.fail(401,'original_employee_password_required');return{invitation:view(row),witness:witness(row)};}
   const observation=await this.observe(witness(row),input.observationAssertion);
   if(observation?.eligible!==true||!isDeepStrictEqual(observation.witness,witness(row)))contract.fail(409,'original_employee_invitation_no_longer_eligible');
   const policy=await new PasswordPolicyEnforcer(client).validatePassword(row.subject_id,input.password);if(!policy.valid)contract.fail(400,'employee_password_policy_rejected');
   const hash=await bcrypt.hash(input.password,12);const credential=UserAggregate.create({id:row.subject_id,username:row.login_name,email:row.grant_source.target.email,passwordHash:hash,roles:['user'],locked:true});
   const validUntil=Math.min(original.expiresAt,observation.validUntil,Math.floor(new Date(row.expires_at).getTime()/1000));
   await admit(row.id,'credentialed',{observation,validUntil});
   await repository.save(credential);
   await client.query('INSERT INTO password_history(user_id,password_hash) VALUES($1,$2)',[row.subject_id,hash]);
   await client.query("UPDATE auth_employee_invitations SET status='credential_pending',revision=revision+1,credential_id=subject_id,credential_revision=$2 WHERE id=$1",[row.id,credential.recordRevision]);
   const current=await this.row(client,row.id);return{invitation:view(current),witness:witness(current)};
  },{proof:original});
 }
 async revoke(input,claims,authorization){
  contract.exact(input,['id','revision','reason','confirm']);contract.identifier(input.id);contract.text(input.reason,10,500);
  if(typeof input.revision!=='string'||!/^[1-9][0-9]{0,18}$/.test(input.revision)||input.confirm!==true)contract.fail(400,'confirmed_employee_invitation_revocation_required');
  return this.owner('revoke',input,claims,authorization,async(client,source,original,admit)=>{
   const row=await this.row(client,input.id,source.tenant.id,true);
   if(row.status==='revoked'&&String(BigInt(input.revision)+1n)===String(row.revision)){
    if(!isDeepStrictEqual(row.revocation_request,input))contract.fail(409,'original_employee_revocation_request_changed');
    return{invitation:view(row),witness:witness(row)};
   }
   if(String(row.revision)!==input.revision)contract.fail(412,'employee_invitation_version_changed');if(!['pending','credential_pending'].includes(row.status))contract.fail(409,'completed_employee_requires_offboarding');
   await admit(row.id,'revoked',{revocationRequest:input});await client.query("UPDATE auth_employee_invitations SET status='revoked',revision=revision+1,revocation_request=$2 WHERE id=$1",[row.id,input]);
   const revoked=await this.row(client,row.id,source.tenant.id);return{invitation:view(revoked),witness:witness(revoked)};
  });
 }
 async identitySource(input,claims){
  contract.exact(input,['witness']);const original=proof('complete',input,claims);contract.identifier(input.witness?.id);
  return this.transaction(async client=>{const row=await this.row(client,input.witness.id);const credential=(await client.query('SELECT id,record_revision,is_locked FROM users WHERE id=$1',[row.subject_id])).rows[0];
   const valid=row.grant_source.issuer===original.issuer&&isDeepStrictEqual(witness(row),input.witness)&&['credential_pending','accepted'].includes(row.status)&&!!credential&&(row.status==='accepted'||credential.is_locked&&String(credential.record_revision)===String(row.credential_revision));
   return{schemaVersion:1,employeeInvitationProtocol:1,witness:witness(row),status:row.status,valid};
  },{proof:original});
 }
 async revokedSource(input,claims){
  contract.exact(input,['witness']);const original=proof('withdraw',input,claims);contract.invitationWitness(input.witness);
  return this.transaction(async client=>{const row=await this.row(client,input.witness.id);const credential=(await client.query('SELECT id,record_revision,is_locked FROM users WHERE id=$1',[row.subject_id])).rows[0];
   const revoked=row.grant_source.issuer===original.issuer&&isDeepStrictEqual(witness(row),input.witness)&&row.status==='revoked'
    &&(!row.credential_event_id||!!credential&&credential.is_locked&&String(credential.record_revision)===String(row.credential_revision));
   return{schemaVersion:1,employeeInvitationProtocol:1,witness:witness(row),revoked};
  },{proof:original});
 }
 async activate(input,claims,authorization){
  contract.exact(input,['id','receipt']);contract.identifier(input.id);const original=proof('activate',input,claims);
  if(!this.accepted)contract.fail(503,'employee_acceptance_source_unavailable');
  return this.transaction(async(client,admit)=>{
   const row=await this.row(client,input.id,null,true);if(row.grant_source.issuer!==original.issuer)contract.fail(401,'original_employee_invitation_issuer_required');if(row.status==='accepted'){
    if(!isDeepStrictEqual(row.identity_receipt,input.receipt))contract.fail(409,'original_employee_acceptance_changed');return{invitation:view(row),witness:witness(row),replayed:true};
   }
   if(row.status!=='credential_pending'||input.receipt?.invitationId!==row.id||input.receipt.subjectId!==row.subject_id||input.receipt.userId!==row.target_id||input.receipt.tenant?.id!==row.tenant.id||input.receipt.confirmed!==true)contract.fail(409,'original_employee_acceptance_required');
   const source=await this.accepted(input,authorization);
   if(source?.active!==true||!isDeepStrictEqual(source.receipt,input.receipt))contract.fail(409,'current_employee_acceptance_required');
   const repository=new PostgresUserRepository(client);const credential=await repository.findById(row.subject_id);
   if(!credential||!credential.isLocked()||credential.recordRevision!==String(row.credential_revision))contract.fail(409,'original_employee_credential_changed');
   await admit(row.id,'accepted');credential.unlock();await repository.save(credential);
   await client.query("UPDATE auth_employee_invitations SET status='accepted',revision=revision+1,identity_receipt=$2 WHERE id=$1",[row.id,input.receipt]);
   const current=await this.row(client,row.id);return{invitation:view(current),witness:witness(current),replayed:false};
  },{proof:original});
 }
 async state(input,claims){
  contract.exact(input,['invitationId','subjectId','userId','tenantId']);for(const value of Object.values(input))contract.identifier(value);const original=proof('state',input,claims);
  return this.transaction(async client=>{
   const row=await this.row(client,input.invitationId);const credential=(await client.query('SELECT id,is_locked,security_revision FROM users WHERE id=$1',[row.subject_id])).rows[0];
   const ready=row.grant_source.issuer===original.issuer&&row.status==='accepted'&&!!credential&&!credential.is_locked&&input.subjectId===row.subject_id&&input.userId===row.target_id&&input.tenantId===row.tenant.id;
   return{schemaVersion:1,employeeInvitationProtocol:1,...input,ready,securityRevision:ready?String(credential.security_revision):null};
  },{proof:original});
 }
}
module.exports={EmployeeInvitations,view,witness};
