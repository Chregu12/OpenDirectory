'use strict';

const blueprint = require('../company-blueprint-contract');
const COMPANY_BLUEPRINT_ASSIGNMENT_PERMISSIONS = Object.freeze(['company.blueprints.assignments.read', 'company.blueprints.assign']);
const { fail, exact, identifier, revision, text, versionNumber, pagination } = blueprint;

function validSource(source, user, userId = null, now = Date.now()) {
  try {
    exact(source, ['schemaVersion', 'companyBlueprintAssignmentsProtocol', 'issuer', 'subject', 'tokenId', 'expiresAt', 'context', 'tenant', 'actorUserId', 'permissions', 'validUntil', 'target']);
    if (source.companyBlueprintAssignmentsProtocol !== 1 || JSON.stringify(source.permissions) !== JSON.stringify(COMPANY_BLUEPRINT_ASSIGNMENT_PERMISSIONS)) return false;
    if (userId === null) {
      if (source.target !== null) return false;
    } else {
      identifier(userId);
      exact(source.target, ['id', 'revision', 'eligibilityRevision', 'enabled', 'deleted']);
      identifier(source.target.id); revision(source.target.eligibilityRevision);
      if (source.target.id !== userId || typeof source.target.enabled !== 'boolean' || typeof source.target.deleted !== 'boolean') return false;
      if (source.target.deleted) {
        if (source.target.revision !== null || source.target.enabled !== false) return false;
      } else revision(source.target.revision);
    }
    const { companyBlueprintAssignmentsProtocol, target, ...base } = source;
    return blueprint.validSource({ ...base, companyBlueprintProtocol: 1, permissions: [...blueprint.COMPANY_BLUEPRINT_PERMISSIONS] }, user, now);
  } catch { return false; }
}

module.exports = { COMPANY_BLUEPRINT_ASSIGNMENT_PERMISSIONS, fail, exact, identifier, revision, text, versionNumber, pagination, validSource };
