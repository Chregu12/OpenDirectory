'use strict';
const {isDeepStrictEqual}=require('node:util');const contract=require('../../../../packages/employee-invitation-contract');
const {sameContext}=require('../../../../packages/identity-authorization-contract');const {sameTenantContext}=require('../../../../packages/tenant-authorization-contract');
const {ownerState}=require('./CompanyOwner');const {AuthorizationState}=require('./AuthorizationState');const {employeeTarget}=require('./EmployeeInvitationAuthority');
class EmployeeInvitationObserver{
 constructor(database){this.database=database;}
 async read(input,proof){
  contract.exact(input,['witness']);const witness=input.witness;
  contract.exact(witness,['id','tenant','subjectId','request','source','createdAt','expiresAt','creationEventId','credential']);contract.identifier(witness.id);contract.identifier(witness.subjectId);contract.identifier(witness.creationEventId);
  const request=contract.createInput(witness.request);const source=witness.source;
  if(proof?.token_use!==contract.PURPOSE||proof.actor_type!=='workload'||proof.scope!=='employees.invitations.observe'||proof.body_sha256!==contract.digest(input)||proof.iss!==source?.issuer||proof.exp*1000<=Date.now())contract.fail(401,'original_employee_observation_proof_required');
  if(witness.id!==request.id||!sameTenantContext(witness.tenant,source.tenant)||source.target?.id!==request.userId||source.target.revision!==request.userRevision||source.actorUserId!==source.context?.userId
   ||JSON.stringify(source.permissions)!==JSON.stringify(contract.PERMISSIONS)||!Number.isFinite(Date.parse(witness.createdAt))||!Number.isFinite(Date.parse(witness.expiresAt))
   ||Date.parse(witness.createdAt)>source.validUntil*1000||Date.parse(witness.expiresAt)-Date.parse(witness.createdAt)!==request.durationHours*3600000)contract.fail(400,'original_employee_invitation_witness_required');
  return this.database.transaction(async client=>{
   const current=await new AuthorizationState({transaction:operation=>operation(client)}).state(source.issuer,source.subject);
   const owner=await ownerState(client,source.actorUserId);const target=await employeeTarget(client,request.userId,witness.tenant.id);
   const eligible=!!(current.active&&sameContext(current.context,source.context)&&sameTenantContext(current.tenant,witness.tenant)&&owner?.active&&owner.issuer===source.issuer&&owner.subject===source.subject&&owner.tenant_id===witness.tenant.id
    &&owner.console_client_id===source.consoleClientId&&target&&!target.enabled&&target.unlinked&&target.ordinary&&isDeepStrictEqual(target,source.target)&&Date.parse(witness.expiresAt)>Date.now());
   return{schemaVersion:1,employeeInvitationProtocol:1,witness,eligible,validUntil:Math.min(proof.exp,Math.floor(Date.parse(witness.expiresAt)/1000))};
  },{readOnly:true});
 }
}
module.exports={EmployeeInvitationObserver};
