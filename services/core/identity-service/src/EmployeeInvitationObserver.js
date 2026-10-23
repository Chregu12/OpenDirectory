'use strict';
const {isDeepStrictEqual}=require('node:util');const contract=require('../../../../packages/employee-invitation-contract');
const {sameContext}=require('../../../../packages/identity-authorization-contract');const {sameTenantContext}=require('../../../../packages/tenant-authorization-contract');
const {ownerState}=require('./CompanyOwner');const {AuthorizationState}=require('./AuthorizationState');const {employeeTarget}=require('./EmployeeInvitationAuthority');
class EmployeeInvitationObserver{
 constructor(database){this.database=database;}
 async ownerCurrent(client,witness){
   const source=witness.source;
   const current=await new AuthorizationState({transaction:operation=>operation(client)}).state(source.issuer,source.subject);
   const owner=await ownerState(client,source.actorUserId);
   return !!(current.active&&sameContext(current.context,source.context)&&sameTenantContext(current.tenant,witness.tenant)&&owner?.active&&owner.issuer===source.issuer&&owner.subject===source.subject&&owner.tenant_id===witness.tenant.id&&owner.console_client_id===source.consoleClientId);
 }
 async current(client,witness){
   const target=await employeeTarget(client,witness.request.userId,witness.tenant.id);
   return !!(await this.ownerCurrent(client,witness)&&target&&!target.enabled&&target.unlinked&&target.ordinary&&isDeepStrictEqual(target,witness.source.target)&&Date.parse(witness.expiresAt)>Date.now());
 }
 async read(input,proof){
  contract.exact(input,['witness']);const witness=contract.invitationWitness(input.witness);
  if(proof?.token_use!==contract.PURPOSE||proof.actor_type!=='workload'||proof.scope!=='employees.invitations.observe'||proof.body_sha256!==contract.digest(input)||proof.iss!==witness.source.issuer||proof.exp*1000<=Date.now())contract.fail(401,'original_employee_observation_proof_required');
  return this.database.transaction(async client=>({schemaVersion:1,employeeInvitationProtocol:1,witness,eligible:await this.current(client,witness),validUntil:Math.min(proof.exp,Math.floor(Date.parse(witness.expiresAt)/1000))}),{readOnly:true});
 }
}
module.exports={EmployeeInvitationObserver};
