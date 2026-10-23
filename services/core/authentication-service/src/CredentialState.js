'use strict';
const contract=require('../../../../packages/credential-authorization-contract');
const {validUuid,validRevision}=require('../../../../packages/identity-authorization-contract');
function fail(status,code){throw Object.assign(new Error(code),{status,code});}
class CredentialState{
 constructor(database){this.database=database;}
 async read(input,proof){
  const now=Math.floor(Date.now()/1000);
  if(!contract.exact(input,['subject'])||!contract.validSubject(input.subject))fail(400,'exact_credential_subject_required');
  if(proof?.actor_type!=='workload'||proof.sub!=='oauth-provider'||proof.aud!==contract.AUDIENCE||proof.token_use!==contract.PURPOSE||proof.scope!==contract.SCOPE
   ||proof.htm!=='POST'||proof.htu!==contract.PATH||proof.request_subject!==input.subject||!contract.uuid(proof.jti)||!Number.isSafeInteger(proof.exp)||!Number.isSafeInteger(proof.iat)||proof.iat>now||proof.exp<=now||proof.exp<=proof.iat||proof.exp-proof.iat>30)fail(401,'original_credential_state_proof_required');
  if(!this.database.isAvailable())fail(503,'credential_state_storage_unavailable');const client=await this.database.getClient();
  try{
   await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');await client.query("SET LOCAL timezone='UTC';SET LOCAL statement_timeout='1500ms'");
   await client.query('SELECT auth_employee_invitation_receiving()');
   const row=validUuid(input.subject)?(await client.query('SELECT id,is_locked,security_revision FROM users WHERE id=$1',[input.subject])).rows[0]:null;
   const result={schemaVersion:1,credentialAuthenticationProtocol:1,subject:input.subject,known:!!row,ready:false,subjectId:row?.id||null,securityRevision:null,invitation:null};
   if(row){
    if(!validRevision(String(row.security_revision))||typeof row.is_locked!=='boolean')fail(503,'credential_state_unconfirmed');
    const invitation=(await client.query('SELECT invitation.*,auth_employee_invitation_valid(id) AS valid FROM auth_employee_invitations invitation WHERE subject_id=$1',[row.id])).rows[0];
    if(invitation&&invitation.valid!==true)fail(503,'original_credential_invitation_evidence_unavailable');
    if(invitation)result.invitation={invitationId:invitation.id,userId:invitation.target_id,tenant:invitation.tenant};
    result.ready=!row.is_locked&&(!invitation||invitation.status==='accepted'&&invitation.credential_id===row.id&&invitation.identity_receipt?.confirmed===true);
    if(result.ready)result.securityRevision=String(row.security_revision);
   }
   if(proof.exp*1000<=Date.now())fail(401,'original_credential_state_proof_expired');
   await client.query('COMMIT');return result;
  }catch(error){await client.query('ROLLBACK').catch(()=>{});if(error.status)throw error;fail(503,'credential_state_unavailable');}finally{client.release();}
 }
}
module.exports={CredentialState};
