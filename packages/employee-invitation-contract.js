'use strict';
const {createHash}=require('node:crypto');
const {validUuid,validRevision,validContext,sameContext}=require('./identity-authorization-contract');
const {validTenantContext}=require('./tenant-authorization-contract');
const SOURCE_PATH='/api/identity/employee-invitations';
const AUTH_BASE='/internal/auth/employee-invitations';
const IDENTITY_BASE='/internal/identity/employee-invitations';
const AUDIENCE='opendirectory-employee-invitations';const PURPOSE='employee-invitation-receiving';const TYPE='od-employee-invitation+jwt';
const PERMISSIONS=Object.freeze(['employees.invitations.read','employees.invitations.create','employees.invitations.revoke']);
function fail(status,code){throw Object.assign(new Error(code),{status,code});}
function exact(value,keys){if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).length!==keys.length||keys.some(key=>!Object.hasOwn(value,key)))fail(400,'exact_employee_invitation_fields_required');}
function identifier(value){if(!validUuid(value)||value!==value.toLowerCase())fail(400,'canonical_employee_invitation_id_required');return value;}
function text(value,min,max){if(typeof value!=='string'||value.trim().length<min||value.length>max||/[\u0000-\u001f\u007f]/.test(value))fail(400,'bounded_employee_invitation_text_required');return value.trim();}
function createInput(value){
 exact(value,['id','userId','userRevision','loginName','durationHours','reason','confirm']);identifier(value.id);identifier(value.userId);
 const loginName=text(value.loginName,3,254);if(!/^[A-Za-z0-9][A-Za-z0-9._@+-]*$/.test(loginName)||!validRevision(value.userRevision)||!Number.isInteger(value.durationHours)||value.durationHours<1||value.durationHours>72||value.confirm!==true)fail(400,'confirmed_employee_invitation_required');
 return{...value,loginName,reason:text(value.reason,10,500)};
}
function parseToken(value){
 if(typeof value!=='string'||value.length!==80)fail(401,'invalid_employee_invitation');const[id,secret]=value.split('.');identifier(id);
 if(!/^[A-Za-z0-9_-]{43}$/.test(secret||'')||Buffer.from(secret,'base64url').toString('base64url')!==secret)fail(401,'invalid_employee_invitation');
 return{id,tokenHash:createHash('sha256').update('employee-invitation:v1|'+value).digest('hex')};
}
function password(value){if(typeof value!=='string'||value.length<12||Buffer.byteLength(value,'utf8')>72||/[\u0000-\u001f\u007f]/.test(value))fail(400,'employee_password_requires_12_characters_and_at_most_72_utf8_bytes');return value;}
function canonical(value){return Array.isArray(value)?value.map(canonical):value&&typeof value==='object'?Object.fromEntries(Object.keys(value).sort().map(key=>[key,canonical(value[key])])):value;}
const digest=value=>createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex');
function source(value,user){
 exact(value,['schemaVersion','employeeInvitationProtocol','issuer','subject','tokenId','expiresAt','context','tenant','actorUserId','permissions','validUntil','consoleClientId','organizationName','target']);
 if(value.schemaVersion!==1||value.employeeInvitationProtocol!==1||user?.actor_type!=='user'||!validContext(user.identity_authorization)||!sameContext(value.context,user.identity_authorization)
  ||value.issuer!==user.iss||value.subject!==user.sub||value.tokenId!==user.jti||value.expiresAt!==user.exp||value.actorUserId!==value.context.userId||!validTenantContext(value.tenant)
  ||JSON.stringify(value.permissions)!==JSON.stringify(PERMISSIONS)||!Number.isSafeInteger(value.validUntil)||!Number.isSafeInteger(user.auth_time)||value.validUntil>Math.min(user.exp,user.auth_time+300)||value.validUntil*1000<=Date.now()
  ||typeof value.consoleClientId!=='string'||!/^[A-Za-z0-9._~-]{1,255}$/.test(value.consoleClientId)||typeof value.organizationName!=='string'||!value.organizationName.trim()||value.organizationName.length>255)fail(503,'original_employee_invitation_authority_unconfirmed');
 if(value.target!==null){const row=value.target;exact(row,['id','revision','username','email','enabled','unlinked','ordinary','tenantGeneration']);identifier(row.id);
  if(!validRevision(row.revision)||!validRevision(row.tenantGeneration)||typeof row.username!=='string'||typeof row.email!=='string'||typeof row.enabled!=='boolean'||typeof row.unlinked!=='boolean'||typeof row.ordinary!=='boolean')fail(503,'original_employee_invitation_target_unconfirmed');}
 return value;
}
module.exports={SOURCE_PATH,AUTH_BASE,IDENTITY_BASE,AUDIENCE,PURPOSE,TYPE,PERMISSIONS,exact,identifier,text,createInput,parseToken,password,digest,source,fail};
