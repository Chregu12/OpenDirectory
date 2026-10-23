'use strict';
const {sameContext,validContext}=require('../../../../packages/identity-authorization-contract');
const {sameTenantContext}=require('../../../../packages/tenant-authorization-contract');
const {acceptsRoleAuthentication}=require('../../../../packages/role-authentication-contract');
const {createTenantStateClient}=require('../../../../packages/oidc-tenant-state');
const contract=require('../../../../packages/company-app-contract');
const {AuthorizationState}=require('./AuthorizationState');const {companyOwner}=require('./CompanyOwner');
class CompanyAppAuthority{
 constructor(database,{issuer=process.env.OIDC_ISSUER||'http://localhost:3001',revalidate=createTenantStateClient()}={}){Object.assign(this,{database,issuer,revalidate});}
 async read(user,authorization){
  if(!this.database.isAvailable())contract.fail(503,'company_app_identity_unavailable');
  if(user?.actor_type!=='user'||user.iss!==this.issuer||!validContext(user.identity_authorization))contract.fail(403,'original_company_app_human_required');
  if(typeof authorization!=='string'||authorization.length>16384||!/^Bearer [A-Za-z0-9._~-]+$/.test(authorization))contract.fail(401,'original_company_app_bearer_required');
  if(!acceptsRoleAuthentication({required:true,maxAgeSeconds:300},user))contract.fail(428,'fresh_company_app_mfa_required');
  const tenant=await this.revalidate(authorization,user);
  const result=await this.database.transaction(async client=>{
   const state=await new AuthorizationState({transaction:operation=>operation(client)}).state(user.iss,user.sub);
   if(!state.active||!sameContext(state.context,user.identity_authorization)||!sameTenantContext(state.tenant,tenant)||!acceptsRoleAuthentication(state.authentication,user))contract.fail(401,'company_app_identity_changed');
   const owner=await companyOwner(client,user);if(owner?.tenant_id!==tenant.id)contract.fail(403,'actual_company_app_owner_required');
   return{schemaVersion:1,companyAppProtocol:1,issuer:user.iss,subject:user.sub,tokenId:user.jti,expiresAt:user.exp,context:state.context,tenant,actorUserId:state.context.userId,
    permissions:[...contract.PERMISSIONS],validUntil:Math.min(user.exp,user.auth_time+Math.min(300,state.authentication.required?state.authentication.maxAgeSeconds:300))};
  },{readOnly:true});
  if(!sameTenantContext(tenant,await this.revalidate(authorization,user))||!acceptsRoleAuthentication({required:true,maxAgeSeconds:300},user))contract.fail(401,'company_app_identity_changed');
  return contract.source(result,user);
 }
}
module.exports={CompanyAppAuthority};
