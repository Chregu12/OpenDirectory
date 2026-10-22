'use strict';
const { exact, identifier, workload, LICENSE_ACTION } = require('./company-automation-contract');
const { validRevision, validUuid } = require('./identity-authorization-contract');
const { validTenantContext } = require('./tenant-authorization-contract');
const { SCHEMA_VERSION } = require('./group-license-lease-contract');
const SOURCE_PATH = '/api/identity/automation/license-source';
const SOURCE_FIELDS = ['schemaVersion', 'companyLicenseAutomationProtocol', 'kind', 'issuer', 'subject', 'tokenId', 'expiresAt', 'clientRevision', 'tenant', 'grantId', 'jobId', 'leaseToken', 'ruleId', 'retryCount', 'validUntil', 'permissions', 'target', 'group'];
const actorId = source => source?.kind === 'application' ? source.grantId : source?.actorUserId;
function validSource(source, user, userId = null, now = Date.now()) {
  try {
    exact(source, SOURCE_FIELDS); const actor = workload(user, user.iss, now);
    if (source.schemaVersion !== 1 || source.companyLicenseAutomationProtocol !== 1 || source.kind !== 'application' || source.issuer !== actor.issuer || source.subject !== actor.clientId
      || source.clientRevision !== actor.clientRevision || source.tokenId !== actor.tokenId || source.expiresAt !== actor.validUntil || !validTenantContext(source.tenant)
      || JSON.stringify(source.permissions) !== JSON.stringify([LICENSE_ACTION]) || !Number.isSafeInteger(source.validUntil) || source.validUntil * 1000 <= now
      || source.validUntil > Math.min(user.exp, Math.floor(now / 1000) + 50) || !Number.isSafeInteger(source.retryCount) || source.retryCount < 0) return false;
    for (const key of ['grantId', 'jobId', 'leaseToken', 'ruleId']) identifier(source[key]);
    if (userId === null) { if (source.target !== null) return false; }
    else {
      identifier(userId); exact(source.target, ['id', 'revision', 'eligibilityRevision', 'enabled', 'deleted']);
      if (source.target.id !== userId || !validRevision(source.target.eligibilityRevision) || typeof source.target.enabled !== 'boolean' || typeof source.target.deleted !== 'boolean'
        || (source.target.deleted ? source.target.enabled !== false || source.target.revision !== null : !validRevision(source.target.revision))) return false;
    }
    if (source.group === null) return userId === null;
    exact(source.group, ['schemaVersion', 'groupId', 'name', 'revision', 'deleted', 'memberIds', 'inactiveMemberIds', 'unresolvedMemberIds', 'memberships']);
    const group = source.group; identifier(group.groupId);
    if (group.schemaVersion !== SCHEMA_VERSION || !validRevision(group.revision) || typeof group.deleted !== 'boolean' || (group.deleted ? group.name !== null : typeof group.name !== 'string' || group.name.length > 255)) return false;
    const seen = new Set();
    for (const key of ['memberIds', 'inactiveMemberIds', 'unresolvedMemberIds']) {
      if (!Array.isArray(group[key]) || group[key].length > 10000) return false;
      for (const id of group[key]) { if (typeof id !== 'string' || !id.length || id.length > 255 || seen.has(id) || key !== 'unresolvedMemberIds' && (!validUuid(id) || id !== id.toLowerCase())) return false; seen.add(id); }
    }
    if (seen.size > 10000 || !Array.isArray(group.memberships) || group.memberships.length !== group.memberIds.length || new Set(group.memberships.map(value => value.userId)).size !== group.memberIds.length) return false;
    const active = new Set(group.memberIds); const membershipIds = new Set();
    for (const member of group.memberships) {
      exact(member, ['userId', 'membershipId', 'eligibilityRevision', 'reviewDeadlineAt']); identifier(member.membershipId);
      if (!active.has(member.userId) || membershipIds.has(member.membershipId) || !validRevision(member.eligibilityRevision) || member.reviewDeadlineAt !== null && (typeof member.reviewDeadlineAt !== 'string' || !Number.isFinite(Date.parse(member.reviewDeadlineAt)) || Date.parse(member.reviewDeadlineAt) < source.validUntil * 1000)) return false;
      membershipIds.add(member.membershipId);
    }
    return !group.deleted || seen.size === 0;
  } catch { return false; }
}
module.exports = { SOURCE_PATH, SOURCE_FIELDS, actorId, validSource };
