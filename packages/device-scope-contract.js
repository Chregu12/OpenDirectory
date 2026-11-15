'use strict';

const { validUuid, validRevision, validContext, sameContext } = require('./identity-authorization-contract');
const { validTenantContext } = require('./tenant-authorization-contract');
const { provenMfa } = require('./mfa-authorization-contract');
const { INVENTORY_PERMISSIONS, inventoryPermissions } = require('./device-inventory-contract');
const COMPLIANCE = require('./device-compliance-contract');
const { isDeepStrictEqual } = require('node:util');
const MAX_GRANTS = 128, MAX_UNITS = 1000;
const BASE = ['id','roleId','roleRevision','scopeType','ouId','targetType','targetId','membershipId','validUntil'];
const PIM = ['activationId','mfaRevision','authTime','issuer','subject','actorContext'];
const FIELDS = ['schemaVersion','issuer','subject','tokenId','expiresAt','context','tenant','actorUserId','permissions','validUntil','target','scope'];
function exact(value, keys) { return !!value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value,key)); }
function uuid(value) { return validUuid(value) && value === value.toLowerCase(); }
function reference(value) { return exact(value,['id','generation']) && uuid(value.id) && validRevision(value.generation); }
function resource(value) { return value === null || exact(value,['deviceId','deviceRevision','revision','ou']) && uuid(value.deviceId) && validRevision(value.deviceRevision)
  && (value.revision === '0' || validRevision(value.revision)) && (value.ou === null || value.revision !== '0' && reference(value.ou)); }
function ordered(values) { return values.every((value,index) => index === 0 || values[index-1] < value); }
function key(grant, available) { return String(available.indexOf(grant.permission)).padStart(2,'0') + ':' + grant.source.id + ':' + (grant.source.activationId || ''); }
function validGrant(grant, envelope, user, available) {
  if (!exact(grant,['permission','source']) || !available.includes(grant.permission)) return false;
  const source = grant.source, pim = !!source && Object.hasOwn(source,'activationId'), scoped = source?.scopeType === 'device-ou';
  if (!exact(source,[...BASE,...(scoped?['ouGeneration']:[]),...(pim?PIM:[])]) || !uuid(source.id) || !uuid(source.roleId) || !validRevision(source.roleRevision)
    || !['tenant','device-ou'].includes(source.scopeType) || (scoped ? !uuid(source.ouId) || !validRevision(source.ouGeneration) || grant.permission === 'devices.compliance.manage' : source.ouId !== null)
    || !uuid(source.targetId) || !validRevision(source.validUntil) || !Number.isSafeInteger(Number(source.validUntil)) || Number(source.validUntil) < envelope.validUntil
    || (source.targetType === 'user' ? source.targetId !== envelope.actorUserId || source.membershipId !== null : source.targetType !== 'group' || !uuid(source.membershipId))) return false;
  return !pim || uuid(source.activationId) && validRevision(source.mfaRevision) && validRevision(source.authTime) && source.mfaRevision === user.mfa_authorization?.revision
    && Number(source.authTime) <= user.auth_time && source.issuer === envelope.issuer && source.subject === envelope.subject && sameContext(source.actorContext,envelope.context);
}
function validEnvelope(value, user, userId = null, compliance = false, selected = null, now = Date.now()) {
  try {
    const available = compliance ? COMPLIANCE.PERMISSIONS : INVENTORY_PERMISSIONS;
    if (!exact(value,FIELDS) || value.schemaVersion !== 2 || user?.actor_type !== 'user' || !validContext(user.identity_authorization) || !provenMfa(user)
      || value.issuer !== user.iss || value.subject !== user.sub || value.tokenId !== user.jti || value.expiresAt !== user.exp
      || !sameContext(value.context,user.identity_authorization) || value.actorUserId !== value.context.userId || !uuid(value.actorUserId) || !validTenantContext(value.tenant)
      || !Number.isSafeInteger(user.auth_time) || user.auth_time > Math.floor(now/1000)+5 || !Number.isSafeInteger(user.exp)
      || !Number.isSafeInteger(value.validUntil) || value.validUntil > Math.min(user.exp,user.auth_time+300) || value.validUntil*1000 <= now
      || !(compliance ? COMPLIANCE.permissions(value.permissions) && userId === null : inventoryPermissions(value.permissions))
      || (userId === null ? value.target !== null : !exact(value.target,['id','revision','enabled']) || value.target.id !== userId || !uuid(userId) || !validRevision(value.target.revision) || typeof value.target.enabled !== 'boolean')) return false;
    const scope = value.scope;
    if (!exact(scope,['protocol','inherent','grants','units','resource']) || scope.protocol !== 1 || !resource(scope.resource) || !isDeepStrictEqual(scope.resource,selected)
      || !Array.isArray(scope.inherent) || !isDeepStrictEqual(scope.inherent,available.filter(permission => scope.inherent.includes(permission)))
      || !Array.isArray(scope.grants) || !scope.grants.length || scope.grants.length > MAX_GRANTS || !scope.grants.every(grant => validGrant(grant,value,user,available))
      || !ordered(scope.grants.map(grant => key(grant,available))) || !scope.grants.some(grant => grant.source.scopeType === 'device-ou')
      || !isDeepStrictEqual(value.permissions,available.filter(permission => scope.inherent.includes(permission) || scope.grants.some(grant => grant.permission === permission)))
      || !Array.isArray(scope.units) || !scope.units.length || scope.units.length > MAX_UNITS || !ordered(scope.units.map(unit => unit.id))) return false;
    if (value.permissions.some(permission => ['devices.inventory.create','devices.inventory.assign'].includes(permission)) && !value.permissions.includes('devices.inventory.read')) return false;
    const roots = new Map();
    for (const grant of scope.grants.filter(grant => grant.source.scopeType === 'device-ou')) {
      if (roots.has(grant.source.ouId) && roots.get(grant.source.ouId) !== grant.source.ouGeneration) return false;
      roots.set(grant.source.ouId,grant.source.ouGeneration);
    }
    if (!scope.units.every(unit => exact(unit,['id','generation','roots']) && uuid(unit.id) && validRevision(unit.generation)
      && Array.isArray(unit.roots) && unit.roots.length > 0 && unit.roots.length <= roots.size && ordered(unit.roots) && unit.roots.every(id => roots.has(id)))) return false;
    return [...roots].every(([id,generation]) => scope.units.some(unit => unit.id === id && unit.generation === generation && unit.roots.includes(id)));
  } catch { return false; }
}
function permits(value, permission, ou) {
  if (!value.permissions.includes(permission)) return false;
  if (value.schemaVersion !== 2) return value.schemaVersion === 1 && !Object.hasOwn(value,'scope');
  const scope = value.scope;
  if (scope.inherent.includes(permission) || scope.grants.some(grant => grant.permission === permission && grant.source.scopeType === 'tenant')) return true;
  return !!ou && scope.units.some(unit => unit.id === ou.id && unit.generation === ou.generation
    && scope.grants.some(grant => grant.permission === permission && unit.roots.includes(grant.source.ouId)));
}
module.exports = { MAX_GRANTS, MAX_UNITS, exact, reference, resource, key, validEnvelope, permits };
