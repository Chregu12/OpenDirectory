'use strict';
const {validContext,sameContext}=require('../../../../packages/identity-authorization-contract');
const {sameTenantContext}=require('../../../../packages/tenant-authorization-contract');
const {acceptsRoleAuthentication}=require('../../../../packages/role-authentication-contract');
const {createTenantStateClient}=require('../../../../packages/oidc-tenant-state');
const {AuthorizationState}=require('./AuthorizationState');const {companyOwner}=require('./CompanyOwner');
const contract=require('../../../../packages/employee-invitation-contract');
async function employeeTarget(client,userId,tenantId){
 const row=(await client.query(`SELECT account.id,account.record_revision,account.username,account.email,account.enabled,account.tenant_generation,
  NOT EXISTS(SELECT 1 FROM identity_subject_links link WHERE link.user_id=account.id) AS unlinked,
  NOT EXISTS(SELECT 1 FROM identity_role_assignments role WHERE role.user_id=account.id AND role.role<>'user' AND role.revoked_at IS NULL)
   AND NOT EXISTS(SELECT 1 FROM identity_pim_eligibilities role WHERE role.user_id=account.id AND role.revoked_at IS NULL)
   AND NOT EXISTS(SELECT 1 FROM identity_company_activations activation WHERE activation.user_id=account.id) AS ordinary
  FROM users account WHERE account.id=$1 AND identity_tenant_id('user',account.id)=$2`,[userId,tenantId])).rows[0];
 return row?{id:row.id,revision:String(row.record_revision),username:row.username,email:row.email,enabled:row.enabled,unlinked:row.unlinked,ordinary:row.ordinary,tenantGeneration:String(row.tenant_generation)}:null;
}
class EmployeeInvitationAuthority{
 constructor(database,{issuer=process.env.OIDC_ISSUER||'http://localhost:3001',revalidate=createTenantStateClient()}={}){Object.assign(this,{database,issuer,revalidate});}
 async read(user,authorization,input){
  contract.exact(input,['userId']);if(input.userId!==null)contract.identifier(input.userId);
  if(!this.database.isAvailable())contract.fail(503,'employee_invitation_identity_unavailable');
  if(user?.actor_type!=='user'||user.iss!==this.issuer||!validContext(user.identity_authorization))contract.fail(403,'original_employee_invitation_human_required');
  if(!acceptsRoleAuthentication({required:true,maxAgeSeconds:300},user))contract.fail(428,'fresh_employee_invitation_mfa_required');
  const tenant=await this.revalidate(authorization,user);
  const result=await this.database.transaction(async client=>{
   const state=await new AuthorizationState({transaction:operation=>operation(client)}).state(user.iss,user.sub);
   if(!state.active||!sameContext(state.context,user.identity_authorization)||!sameTenantContext(state.tenant,tenant)||!acceptsRoleAuthentication(state.authentication,user))contract.fail(401,'employee_invitation_identity_changed');
   const owner=await companyOwner(client,user);if(owner?.tenant_id!==tenant.id)contract.fail(403,'actual_employee_invitation_owner_required');
   const organization=(await client.query('SELECT name FROM identity_organization_profiles WHERE tenant_id=$1',[tenant.id])).rows[0];
   let target=null;
   if(input.userId!==null){
    target=await employeeTarget(client,input.userId,tenant.id);if(!target)contract.fail(404,'own_employee_invitation_target_not_found');
   }
   return{schemaVersion:1,employeeInvitationProtocol:1,issuer:user.iss,subject:user.sub,tokenId:user.jti,expiresAt:user.exp,context:state.context,tenant,actorUserId:state.context.userId,permissions:[...contract.PERMISSIONS],
    validUntil:Math.min(user.exp,user.auth_time+Math.min(300,state.authentication.required?state.authentication.maxAgeSeconds:300)),consoleClientId:owner.console_client_id,organizationName:organization?.name,target};
  },{readOnly:true});
  if(!sameTenantContext(tenant,await this.revalidate(authorization,user))||!acceptsRoleAuthentication({required:true,maxAgeSeconds:300},user))contract.fail(401,'employee_invitation_identity_changed');
  return contract.source(result,user);
 }
}
module.exports={EmployeeInvitationAuthority,employeeTarget};
