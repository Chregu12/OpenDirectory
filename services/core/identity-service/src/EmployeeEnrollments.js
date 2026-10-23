'use strict';
const {randomUUID}=require('node:crypto');const {isDeepStrictEqual}=require('node:util');
const contract=require('../../../../packages/employee-invitation-contract');const {EmployeeCredentialSource}=require('./EmployeeCredentialSource');
const {EmployeeInvitationObserver}=require('./EmployeeInvitationObserver');const {DirectoryUsers,userFromRow,userEtag}=require('./DirectoryUsers');
function privateProof(operation,input,claims){
 const now=Math.floor(Date.now()/1000);
 if(claims?.sub!=='oauth-provider'||claims.actor_type!=='workload'||claims.aud!==contract.AUDIENCE||claims.token_use!==contract.PURPOSE||claims.scope!=='employees.invitations.'+operation
  ||claims.htm!=='POST'||claims.htu!==(operation==='activate'?contract.AUTH_BASE:contract.IDENTITY_BASE)+'/'+operation||claims.body_sha256!==contract.digest(input)||claims.owner_sha256!==null
  ||typeof claims.iss!=='string'||!claims.iss||!Number.isSafeInteger(claims.iat)||!Number.isSafeInteger(claims.exp)||claims.iat>now||claims.exp<=now||claims.exp<=claims.iat||claims.exp-claims.iat>30)contract.fail(401,'original_employee_enrollment_proof_required');
 contract.identifier(claims.jti);return{issuer:claims.iss,subject:'oauth-provider',tokenId:claims.jti,expiresAt:claims.exp};
}
const receipt=row=>({schemaVersion:1,employeeInvitationProtocol:1,invitationId:row.id,subjectId:row.subject,userId:row.user_id,tenant:row.tenant,linkRevision:String(row.link_revision),acceptanceEventId:row.creation_event_id,confirmed:true});
class EmployeeEnrollments{
 constructor(database,{credentials=new EmployeeCredentialSource()}={}){this.database=database;this.credentials=credentials;this.observer=new EmployeeInvitationObserver(database);}
 async transaction(operation,{readOnly=false}={}){
  if(!this.database.isAvailable())contract.fail(503,'employee_enrollment_storage_unavailable');
  try{return await this.database.transaction(async client=>{await client.query("SET LOCAL timezone='UTC'");await client.query('SELECT identity_employee_receiving()');return operation(client);},{readOnly,actor:readOnly?undefined:'oauth-provider'});}
  catch(error){if(error.status)throw error;throw Object.assign(new Error('employee_enrollment_outcome_unconfirmed'),{status:error.code==='23505'?409:503,code:error.code==='23505'?'employee_enrollment_conflict':'employee_enrollment_outcome_unconfirmed',cause:error});}
 }
 async retained(client,id,lock=false){
  const row=(await client.query(`SELECT enrollment.*,identity_employee_valid(id) AS valid FROM identity_employee_enrollments enrollment WHERE id=$1${lock?' FOR UPDATE':''}`,[id])).rows[0];
  if(row&&row.valid!==true)contract.fail(503,'employee_enrollment_evidence_unavailable');return row||null;
 }
 async unchanged(client,row,{requireActiveTenant=true}={}){
  const current=(await client.query('SELECT identity_directory_user_state(to_jsonb(account)) AS state FROM users account WHERE id=$1',[row.user_id])).rows[0]?.state;
  const link=(await client.query('SELECT user_id,authorization_revision FROM identity_subject_links WHERE issuer=$1 AND subject=$2',[row.issuer,row.subject])).rows[0];
  const tenant=(await client.query("SELECT enabled AND jsonb_build_object('id',id,'version',version::text,'generation',generation::text)=$2::jsonb AS current FROM identity_tenants WHERE id=$1",[row.tenant_id,row.tenant])).rows[0];
  const unchanged=isDeepStrictEqual(current,row.user_after)||!requireActiveTenant&&(await client.query('SELECT identity_employee_withdrawal_unchanged($1,$2) AS valid',[row.id,current])).rows[0]?.valid===true;
  return row.state==='active'&&unchanged&&link?.user_id===row.user_id&&String(link.authorization_revision)===String(row.link_revision)&&!!tenant&&(!requireActiveTenant||tenant.current===true);
 }
 async mutate(client,witness,original,authSource,enabled){
  const before=(await client.query('SELECT identity_directory_user_state(to_jsonb(account)) AS state FROM users account WHERE id=$1',[witness.request.userId])).rows[0]?.state;
  if(!before)contract.fail(409,'original_employee_recipient_missing');
  const validUntil=enabled?Math.min(original.expiresAt,Math.floor(Date.parse(witness.expiresAt)/1000)):original.expiresAt;
  const operationId=randomUUID();const mutation={operationId,issuer:original.issuer,subject:'oauth-provider',context:null,tenant:witness.tenant,rolesSnapshot:null,validUntil,
   target:{id:witness.request.userId,action:'update',before,expectedValues:{username:before.username,email:before.email,displayName:before.display_name??null,department:before.department??null,title:before.title??null,enabled}}};
  const ownerRolesSnapshot=enabled?(await client.query('SELECT identity_subject_link_role_state($1) AS state',[witness.source.actorUserId])).rows[0].state:null;
  const scope={operationId,action:enabled?'complete':'withdraw',proof:original,witness,authSource,validUntil,mutation,ownerRolesSnapshot};
  await client.query("SELECT set_config('opendirectory.employee_enrollment',$1,true),set_config('opendirectory.user_mutation',$2,true)",[JSON.stringify(scope),JSON.stringify(mutation)]);
  const bound={isAvailable:()=>true,transaction:operation=>operation(client),write:(...args)=>client.query(...args)};
  await new DirectoryUsers(bound).update(witness.request.userId,{enabled},userEtag(userFromRow(before)),'oauth-provider');return{mutation,operationId};
 }
 async complete(input,claims,authorization){
  contract.exact(input,['witness']);const original=privateProof('complete',input,claims);const witness=contract.invitationWitness(input.witness);
  if(original.issuer!==witness.source.issuer||!witness.credential)contract.fail(409,'original_employee_credential_required');
  const source=await this.credentials.read('complete',input,authorization);
  if(!source.valid)contract.fail(409,'current_original_employee_credential_required');
  return this.transaction(async client=>{
   await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',['employee-enrollment:'+witness.id]);
   const previous=await this.retained(client,witness.id,true);
   if(previous){if(!isDeepStrictEqual(previous.witness,witness))contract.fail(409,'original_employee_enrollment_changed');return{receipt:receipt(previous),active:await this.unchanged(client,previous),replayed:true};}
   if(source.status!=='credential_pending')contract.fail(409,'original_pending_employee_credential_required');
   await client.query('SELECT id FROM identity_tenants WHERE id=$1 FOR SHARE',[witness.tenant.id]);
   await client.query('SELECT id FROM users WHERE id=ANY($1::uuid[]) ORDER BY id FOR UPDATE',[[witness.source.actorUserId,witness.request.userId].sort()]);
   if(!await this.observer.current(client,witness))contract.fail(409,'original_employee_invitation_no_longer_eligible');
   await client.query("SET LOCAL statement_timeout='10s'");
   const {mutation,operationId}=await this.mutate(client,witness,original,source,true);
   const link=(await client.query('INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES($1,$2,$3) RETURNING authorization_revision',[original.issuer,witness.subjectId,witness.request.userId])).rows[0];
   const after=(await client.query('SELECT identity_directory_user_state(to_jsonb(account)) AS state FROM users account WHERE id=$1',[witness.request.userId])).rows[0].state;
   await client.query(`INSERT INTO identity_employee_enrollments(id,tenant_id,issuer,subject,user_id,tenant,witness,console_client_id,link_revision,state,revision,acceptance_mutation,user_after,creation_event_id,event_id)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'active',1,$10,$11,$12,$12)`,[witness.id,witness.tenant.id,original.issuer,witness.subjectId,witness.request.userId,witness.tenant,witness,witness.source.consoleClientId,String(link.authorization_revision),mutation,after,operationId]);
   if(!await this.observer.ownerCurrent(client,witness)||!isDeepStrictEqual(source,await this.credentials.read('complete',input,authorization)))contract.fail(409,'employee_enrollment_source_changed');
   return{receipt:receipt(await this.retained(client,witness.id)),active:true,replayed:false};
  });
 }
 async acceptedSource(input,claims){
  contract.exact(input,['id','receipt']);contract.identifier(input.id);const original=privateProof('activate',input,claims);
  return this.transaction(async client=>{const row=await this.retained(client,input.id);
   const actual=row?receipt(row):null;const active=!!row&&row.issuer===original.issuer&&isDeepStrictEqual(actual,input.receipt)&&await this.unchanged(client,row)&&await this.observer.ownerCurrent(client,row.witness);
   return{schemaVersion:1,employeeInvitationProtocol:1,receipt:actual,active};
  },{readOnly:true});
 }
 async withdraw(input,claims,authorization){
  contract.exact(input,['witness']);const original=privateProof('withdraw',input,claims);const witness=contract.invitationWitness(input.witness);
  if(original.issuer!==witness.source.issuer)contract.fail(401,'original_employee_invitation_issuer_required');
  const source=await this.credentials.read('withdraw',input,authorization);if(!source.revoked)contract.fail(409,'actual_employee_invitation_revocation_required');
  return this.transaction(async client=>{
   await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',['employee-enrollment:'+witness.id]);const row=await this.retained(client,witness.id,true);
   if(!row)return{invitationId:witness.id,withdrawn:true,changed:false,receipt:null};
   if(!isDeepStrictEqual(row.witness,witness))contract.fail(409,'original_employee_enrollment_changed');
   if(row.state==='withdrawn')return{invitationId:row.id,withdrawn:true,changed:false,receipt:{...receipt(row),withdrawn:true,withdrawalEventId:row.event_id}};
   await client.query('SELECT id FROM users WHERE id=$1 FOR UPDATE',[row.user_id]);if(!await this.unchanged(client,row,{requireActiveTenant:false}))contract.fail(409,'changed_partial_employee_requires_review');
   const {mutation,operationId}=await this.mutate(client,witness,original,source,false);
   const removed=await client.query('DELETE FROM identity_subject_links WHERE issuer=$1 AND subject=$2 AND user_id=$3 AND authorization_revision=$4',[row.issuer,row.subject,row.user_id,row.link_revision]);
   if(removed.rowCount!==1)contract.fail(409,'original_employee_link_changed');
   await client.query("UPDATE identity_employee_enrollments SET state='withdrawn',revision=revision+1,event_id=$2,withdrawal_mutation=$3 WHERE id=$1",[row.id,operationId,mutation]);
   if(!isDeepStrictEqual(source,await this.credentials.read('withdraw',input,authorization)))contract.fail(409,'employee_revocation_source_changed');
   return{invitationId:row.id,withdrawn:true,changed:true,receipt:{...receipt(row),withdrawn:true,withdrawalEventId:operationId}};
  });
 }
}
module.exports={EmployeeEnrollments,receipt};
