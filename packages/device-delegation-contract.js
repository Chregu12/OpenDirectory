'use strict';
const { validUuid, validRevision, sameContext } = require('./identity-authorization-contract');
const BASE = ['id','roleId','roleRevision','scopeType','ouId','targetType','targetId','membershipId','validUntil'];
const PIM = ['activationId','mfaRevision','authTime','issuer','subject','actorContext'];
function exact(value, fields) {
 return value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === fields.length && fields.every(key => Object.hasOwn(value,key));
}
function validDelegation(envelope, user) {
 const delegation=envelope.delegation;
 if(!Array.isArray(envelope.permissions)||!Number.isSafeInteger(envelope.validUntil)||!exact(delegation,['grants'])||!Array.isArray(delegation.grants)||delegation.grants.length!==envelope.permissions.length)return false;
 return delegation.grants.every((grant,index)=>{
  if(!exact(grant,['permission','source'])||grant.permission!==envelope.permissions[index])return false;
  const source=grant.source,pim=!!source&&Object.hasOwn(source,'activationId');
  if(!exact(source,[...BASE,...(pim?PIM:[])])||!validUuid(source.id)||!validUuid(source.roleId)||!validRevision(source.roleRevision)
   ||source.scopeType!=='tenant'||source.ouId!==null||!validUuid(source.targetId)||!validRevision(source.validUntil)
   ||!Number.isSafeInteger(Number(source.validUntil))||Number(source.validUntil)<envelope.validUntil
   ||(source.targetType==='user'?source.targetId!==envelope.actorUserId||source.membershipId!==null:source.targetType!=='group'||!validUuid(source.membershipId)))return false;
  return !pim||validUuid(source.activationId)&&validRevision(source.mfaRevision)&&validRevision(source.authTime)
   &&source.issuer===envelope.issuer&&source.subject===envelope.subject&&sameContext(source.actorContext,envelope.context)
   &&(!user||source.mfaRevision===user.mfa_authorization?.revision&&Number(source.authTime)<=user.auth_time);
 });
}
module.exports={validDelegation};
