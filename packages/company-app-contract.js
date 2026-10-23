'use strict';
const {validContext,sameContext,validUuid}=require('./identity-authorization-contract');
const {validTenantContext}=require('./tenant-authorization-contract');
const SOURCE_PATH='/api/identity/company-apps';
const TENANT_PATH='/internal/identity/company-app-tenant';
const TENANT_PURPOSE='identity-company-app-tenant-request';
const PERMISSIONS=Object.freeze(['company.apps.read','company.apps.create','company.apps.update','company.apps.credentials.rotate','company.apps.delete']);
function fail(status,code){throw Object.assign(new Error(code),{status,code});}
function exact(value,fields){if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).length!==fields.length||fields.some(key=>!Object.hasOwn(value,key)))fail(400,'exact_company_app_fields_required');}
function identifier(value){if(!validUuid(value)||value!==value.toLowerCase())fail(400,'canonical_company_app_id_required');return value;}
function source(value,user){
 exact(value,['schemaVersion','companyAppProtocol','issuer','subject','tokenId','expiresAt','context','tenant','actorUserId','permissions','validUntil']);
 if(value.schemaVersion!==1||value.companyAppProtocol!==1||user?.actor_type!=='user'||!validContext(user.identity_authorization)||!sameContext(value.context,user.identity_authorization)
  ||value.issuer!==user.iss||value.subject!==user.sub||value.tokenId!==user.jti||value.expiresAt!==user.exp||value.actorUserId!==value.context.userId||!validTenantContext(value.tenant)
  ||JSON.stringify(value.permissions)!==JSON.stringify(PERMISSIONS)||!Number.isSafeInteger(value.validUntil)||!Number.isSafeInteger(user.auth_time)
  ||value.validUntil>Math.min(user.exp,user.auth_time+300)||value.validUntil*1000<=Date.now())fail(503,'original_company_app_authority_unconfirmed');return value;
}
function metadata(body,creating=false){
 exact(body,creating?['requestId','name','purpose','reason','confirm']:['name','enabled','purpose','reason','confirm']);
 if(creating)identifier(body.requestId);
 if(creating&&!validUuid(body.requestId)||!creating&&typeof body.enabled!=='boolean'||typeof body.name!=='string'||body.name.trim().length<1||body.name.trim().length>160
  ||typeof body.reason!=='string'||body.reason.trim().length<10||body.reason.trim().length>500||/[\u0000-\u001f\u007f]/.test(body.name+body.reason)
  ||!['none','company-automation'].includes(body.purpose)||body.confirm!==true)fail(400,'confirmed_company_app_metadata_required');
 return {...body,name:body.name.trim(),reason:body.reason.trim()};
}
module.exports={SOURCE_PATH,TENANT_PATH,TENANT_PURPOSE,PERMISSIONS,exact,identifier,source,metadata,fail};
