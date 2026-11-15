'use strict';

const Scope = require('./device-scope-contract');
const { validRevision } = require('./identity-authorization-contract');
function exact(value,keys) { return !!value && typeof value==='object' && !Array.isArray(value) && Object.keys(value).length===keys.length && keys.every(key=>Object.hasOwn(value,key)); }
function uuid(value) { return typeof value==='string' && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(value); }
function validSource(value,user,workflowId,userId,selected=null,now=Date.now()) {
 try {
  if(!exact(value,['schemaVersion','deviceOffboardingReturnsProtocol','inventory','target','parent']) || value.schemaVersion!==2 || value.deviceOffboardingReturnsProtocol!==2
   || value.inventory?.schemaVersion!==2 || !Scope.validEnvelope(value.inventory,user,userId,false,selected,now)
   || !['devices.inventory.read','devices.inventory.assign'].every(permission=>value.inventory.permissions.includes(permission)))return false;
  const target=value.target,parent=value.parent;
  return exact(target,['id','enabled','eligibilityRevision']) && uuid(userId) && target.id===userId && target.enabled===false && value.inventory.target.enabled===false
   && userId!==value.inventory.actorUserId && validRevision(target.eligibilityRevision)
   && exact(parent,['workflowId','tenantId','userId','action','operationId','afterRevision','afterEligibilityRevision','createdAt','deliveryStatus'])
   && uuid(workflowId) && parent.workflowId===workflowId && parent.tenantId===value.inventory.tenant.id && parent.userId===userId
   && ['disabled','already_disabled'].includes(parent.action) && (parent.action==='disabled'?uuid(parent.operationId):parent.operationId===null)
   && validRevision(parent.afterRevision) && parent.afterEligibilityRevision===target.eligibilityRevision && parent.deliveryStatus==='pending'
   && typeof parent.createdAt==='string' && Number.isFinite(Date.parse(parent.createdAt)) && new Date(parent.createdAt).toISOString()===parent.createdAt && Date.parse(parent.createdAt)<=now;
 } catch { return false; }
}
module.exports = { validSource };
