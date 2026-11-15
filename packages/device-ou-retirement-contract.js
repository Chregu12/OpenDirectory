'use strict';
const { validUuid, validRevision, validContext, sameContext } = require('./identity-authorization-contract');
const { validTenantContext } = require('./tenant-authorization-contract');
const { provenMfa } = require('./mfa-authorization-contract');
const { validDelegation } = require('./device-delegation-contract');
const { exact, fail } = require('./device-ou-contract');
const uuid = value => validUuid(value) && value === value.toLowerCase();
function input(value) {
  if (!exact(value, ['action', 'ouId', 'generation', 'revision', 'fenceRevision']) || !['prepare', 'cancel'].includes(value.action) || !uuid(value.ouId)
    || !validRevision(value.generation) || !validRevision(value.revision) || !(value.fenceRevision === '0' || validRevision(value.fenceRevision))
    || value.action === 'cancel' && value.fenceRevision === '0') fail(400, 'Exact original OU retirement selection required');
  return value;
}
function validSource(value, user, selected, now = Date.now()) {
  try {
    input(selected);
    return Boolean(exact(value, ['schemaVersion', 'deviceOuRetirementProtocol', 'issuer', 'subject', 'tokenId', 'expiresAt', 'context', 'tenant', 'actorUserId', 'permissions', 'validUntil', 'action', 'target', 'fenceRevision', 'protected', 'delegation'])
      && value.schemaVersion === 1 && value.deviceOuRetirementProtocol === 1 && user?.actor_type === 'user' && provenMfa(user) && validContext(user.identity_authorization)
      && value.issuer === user.iss && value.subject === user.sub && typeof value.issuer === 'string' && value.issuer.length > 0 && typeof value.subject === 'string' && value.subject.length > 0
      && typeof value.tokenId === 'string' && value.tokenId.length > 0 && value.tokenId === user.jti && value.expiresAt === user.exp && Number.isSafeInteger(user.exp)
      && sameContext(value.context, user.identity_authorization) && value.actorUserId === user.identity_authorization.userId && uuid(value.actorUserId) && validTenantContext(value.tenant)
      && Array.isArray(value.permissions) && value.permissions.length === 1 && value.permissions[0] === 'ous.delete'
      && Number.isSafeInteger(user.auth_time) && user.auth_time <= Math.floor(now / 1000) + 5 && Number.isSafeInteger(value.validUntil)
      && value.validUntil * 1000 > now && value.validUntil <= Math.min(user.exp, user.auth_time + 300)
      && value.action === selected.action && value.fenceRevision === selected.fenceRevision && typeof value.protected === 'boolean'
      && exact(value.target, ['id', 'generation', 'revision']) && value.target.id === selected.ouId && value.target.generation === selected.generation && value.target.revision === selected.revision
      && (value.delegation === null || validDelegation(value, user)));
  } catch { return false; }
}
module.exports = { input, validSource };
