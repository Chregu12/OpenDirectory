'use strict';

const { validRevision } = require('../../../../../packages/identity-authorization-contract');
const { exact, identifier, text, expectedVersion } = require('../../../../../packages/company-license-contract');

function fail(message) { throw Object.assign(new Error(message), { status: 400 }); }
function revision(value) { if (!validRevision(value)) fail('Exact original eligibility revision required'); return value; }
function sources(values) {
  if (!Array.isArray(values) || values.length > 10000) fail('Complete bounded company source manifest required');
  const result = values.map(value => {
    exact(value, ['sourceType', 'sourceId', 'grantId']); identifier(value.grantId);
    if (value.sourceType === 'direct') { if (value.sourceId !== 'direct') fail('Exact manual direct source required'); }
    else if (value.sourceType === 'blueprint') identifier(value.sourceId);
    else fail('Unsupported company license source');
    return { sourceType: value.sourceType, sourceId: value.sourceId, grantId: value.grantId };
  });
  if (new Set(result.map(value => value.sourceType + ':' + value.sourceId)).size !== result.length
    || new Set(result.map(value => value.grantId)).size !== result.length) fail('Duplicate company source incarnation');
  const ordered = [...result].sort((left, right) => left.sourceType.localeCompare(right.sourceType) || left.sourceId.localeCompare(right.sourceId) || left.grantId.localeCompare(right.grantId));
  if (JSON.stringify(result) !== JSON.stringify(ordered)) fail('Canonical ordered company source manifest required');
  return result;
}
function manualValues(action, input) {
  exact(input, action === 'manual_assign' ? ['userId', 'eligibilityRevision', 'assignmentId', 'sources', 'reason', 'confirm'] : ['userId', 'eligibilityRevision', 'sources', 'reason', 'confirm']);
  identifier(input.userId); revision(input.eligibilityRevision);
  if (input.confirm !== true) fail('Explicit company source confirmation required');
  const captured = sources(input.sources); const manual = captured.filter(source => source.sourceType === 'direct');
  if (action === 'manual_assign') {
    if (input.assignmentId !== null) identifier(input.assignmentId);
    if ((input.assignmentId === null) !== (captured.length === 0) || manual.length) fail('Exact unallocated manual source required');
  } else if (manual.length !== 1) fail('Exactly one original manual source required');
  return { userId: input.userId, eligibilityRevision: input.eligibilityRevision, assignmentId: input.assignmentId ?? null, sources: captured, reason: text(input.reason, 10, 500), confirm: true };
}
function poolCapture(value) {
  exact(value, ['poolId', 'poolRevision', 'assignmentId', 'sources']); identifier(value.poolId); revision(value.poolRevision); identifier(value.assignmentId);
  const captured = sources(value.sources); if (!captured.length) fail('A captured allocation requires actual sources');
  return { poolId: value.poolId, poolRevision: value.poolRevision, assignmentId: value.assignmentId, sources: captured };
}
function bindingCapture(value) {
  exact(value, ['id', 'revision']); identifier(value.id); revision(value.revision); return { id: value.id, revision: value.revision };
}
function retirementValues(input) {
  exact(input, ['workflowId', 'eligibilityRevision', 'assignments', 'bindings', 'reason', 'confirm']);
  if (input.workflowId !== null) identifier(input.workflowId); revision(input.eligibilityRevision);
  if (input.confirm !== true || !Array.isArray(input.assignments) || input.assignments.length > (input.workflowId === null ? 25 : 10000) || !Array.isArray(input.bindings) || input.bindings.length > 10000) fail('Explicit bounded source retirement required');
  const assignments = input.assignments.map(poolCapture); const bindings = input.bindings.map(bindingCapture);
  if (assignments.reduce((total, value) => total + value.sources.length, 0) > 10000) fail('Complete retirement exceeds the bounded source manifest');
  if (input.workflowId === null && (bindings.length || assignments.some(value => value.sources.some(source => source.sourceType !== 'direct')))) fail('Blueprint retirement requires the original offboarding workflow');
  if (!assignments.length && !bindings.length) fail('Capture at least one allocation or blueprint binding');
  if (new Set(assignments.map(value => value.poolId)).size !== assignments.length || new Set(assignments.map(value => value.assignmentId)).size !== assignments.length
    || new Set(bindings.map(value => value.id)).size !== bindings.length) fail('Duplicate source retirement capture');
  return { workflowId: input.workflowId, eligibilityRevision: input.eligibilityRevision, assignments, bindings, reason: text(input.reason, 10, 500), confirm: true };
}
function operationKey(value) { return identifier(value); }
function manualCommand(action, poolId, projectionId, input, expected, key, correlationId) {
  const values = manualValues(action, input); identifier(poolId); operationKey(key); identifier(correlationId);
  if (action === 'manual_revoke') identifier(projectionId);
  const manual = values.sources.find(source => source.sourceType === 'direct');
  return { id: key, correlationId, action, assignmentId: null, expectedRevision: '0', userId: values.userId, eligibilityRevision: values.eligibilityRevision,
    blueprintId: null, version: null, pools: [{ poolId, poolRevision: expectedVersion(poolId, expected) }], reason: values.reason,
    values: { projectionId: action === 'manual_assign' ? values.assignmentId : projectionId, grantId: manual?.grantId || null, sources: values.sources } };
}

module.exports = { sources, revision, manualValues, poolCapture, bindingCapture, retirementValues, operationKey, manualCommand };
