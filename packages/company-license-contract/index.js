'use strict';

const { validUuid, validRevision } = require('../identity-authorization-contract');
const COMPANY_LICENSE_PERMISSIONS = Object.freeze(['company.apps.read', 'company.apps.create', 'company.apps.assign']);
function fail(status, message) { throw Object.assign(new Error(message), { status }); }
function exact(input, fields) {
  if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).length !== fields.length || fields.some(field => !Object.hasOwn(input, field))) fail(400, 'Exact company license fields required');
}
function text(value, minimum, maximum) {
  if (typeof value !== 'string' || /[\u0000-\u001f\u007f-\u009f]/u.test(value)) fail(400, 'Invalid company license text');
  value = value.trim(); if ([...value].length < minimum || [...value].length > maximum) fail(400, 'Invalid company license text'); return value;
}
function identifier(value) { if (!validUuid(value) || value !== value.toLowerCase()) fail(400, 'Canonical company license UUID required'); return value; }
function poolValues(input) {
  exact(input, ['name', 'vendor', 'description', 'totalSeats', 'reason']);
  if (!Number.isInteger(input.totalSeats) || input.totalSeats < 1 || input.totalSeats > 10000) fail(400, 'A finite pool needs 1–10000 seats');
  return { name: text(input.name, 1, 160), vendor: text(input.vendor, 1, 160), description: text(input.description, 0, 2000), totalSeats: input.totalSeats, reason: text(input.reason, 10, 500) };
}
function assignmentValues(input) {
  exact(input, ['userId', 'reason', 'confirm']); if (input.confirm !== true) fail(400, 'Explicit company license confirmation required');
  return { userId: identifier(input.userId), reason: text(input.reason, 10, 500), confirm: true };
}
function poolUpdateValues(input) {
  exact(input, ['name', 'vendor', 'description', 'totalSeats', 'reason', 'confirm']);
  if (input.confirm !== true) fail(400, 'Explicit company catalog update confirmation required');
  const { confirm, ...values } = input;
  return { ...poolValues(values), confirm };
}
function returnValues(input) {
  exact(input, ['reason', 'confirm', 'assignments']);
  if (input.confirm !== true || !Array.isArray(input.assignments) || input.assignments.length < 1 || input.assignments.length > 25) fail(400, 'Confirm one captured page of 1–25 company license returns');
  const assignments = input.assignments.map(item => {
    exact(item, ['poolId', 'assignmentId', 'poolRevision']);
    identifier(item.poolId); identifier(item.assignmentId);
    if (!validRevision(item.poolRevision)) fail(400, 'Exact captured company pool revision required');
    return { poolId: item.poolId, assignmentId: item.assignmentId, poolRevision: item.poolRevision };
  });
  if (new Set(assignments.map(item => item.poolId)).size !== assignments.length || new Set(assignments.map(item => item.assignmentId)).size !== assignments.length) fail(400, 'Duplicate company license return');
  return { reason: text(input.reason, 10, 500), confirm: true, assignments };
}
function offboardingIntent(input) {
  exact(input, ['workflowId', 'userId', 'userRevision', 'eligibilityRevision', 'reason', 'confirm']);
  identifier(input.workflowId); identifier(input.userId);
  if (input.confirm !== true || !validRevision(input.userRevision) || !validRevision(input.eligibilityRevision)) fail(400, 'Confirmed current employee offboarding versions required');
  return { workflowId: input.workflowId, userId: input.userId, userRevision: input.userRevision, eligibilityRevision: input.eligibilityRevision, reason: text(input.reason, 10, 500), confirm: true };
}
function offboardingContinuation(input) {
  exact(input, ['confirm', 'reason', 'userRevision', 'assignments']);
  if (input.confirm !== true || !validRevision(input.userRevision) || !Array.isArray(input.assignments) || input.assignments.length > 25) fail(400, 'Confirmed captured offboarding continuation required');
  const assignments = input.assignments.length ? returnValues({ reason: input.reason, confirm: true, assignments: input.assignments }).assignments : [];
  return { confirm: true, reason: text(input.reason, 10, 500), userRevision: input.userRevision, assignments };
}
function groupCleanupQuery(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).some(field => !['workflowId', 'page', 'limit'].includes(field))) fail(400, 'Exact offboarding group selectors required');
  identifier(input.workflowId);
  const { page, limit } = pagination({ ...(input.page === undefined ? {} : { page: input.page }), ...(input.limit === undefined ? {} : { limit: input.limit }) });
  if (limit !== 25) fail(400, 'Offboarding groups require pages of 25');
  return { workflowId: input.workflowId, page, limit };
}
function groupCleanupValues(input) {
  exact(input, ['workflowId', 'eligibilityRevision', 'reason', 'confirm', 'memberships']);
  identifier(input.workflowId);
  if (input.confirm !== true || !validRevision(input.eligibilityRevision) || !Array.isArray(input.memberships) || input.memberships.length < 1 || input.memberships.length > 25) fail(400, 'Confirm one captured page of 1–25 group memberships');
  const memberships = input.memberships.map(member => {
    exact(member, ['groupId', 'groupRevision', 'membershipId']); identifier(member.groupId); identifier(member.membershipId);
    if (!validRevision(member.groupRevision)) fail(400, 'Exact captured group revision required');
    return { groupId: member.groupId, groupRevision: member.groupRevision, membershipId: member.membershipId };
  });
  if (new Set(memberships.map(member => member.groupId)).size !== memberships.length || new Set(memberships.map(member => member.membershipId)).size !== memberships.length) fail(400, 'Duplicate offboarding group membership');
  return { workflowId: input.workflowId, eligibilityRevision: input.eligibilityRevision, reason: text(input.reason, 10, 500), confirm: true, memberships };
}
function accessCleanupCapabilitiesQuery(input) {
  exact(input, ['workflowId']);
  return { workflowId: identifier(input.workflowId) };
}
function accessCleanupQuery(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).some(field => !['workflowId', 'kind', 'page', 'limit'].includes(field))) fail(400, 'Exact offboarding access selectors required');
  identifier(input.workflowId);
  if (!['role', 'eligibility'].includes(input.kind)) fail(400, 'Explicit offboarding access kind required');
  const { page, limit } = pagination({ ...(input.page === undefined ? {} : { page: input.page }), ...(input.limit === undefined ? {} : { limit: input.limit }) });
  if (limit !== 25) fail(400, 'Offboarding access requires pages of 25');
  return { workflowId: input.workflowId, kind: input.kind, page, limit };
}
function accessCleanupValues(input) {
  exact(input, ['workflowId', 'eligibilityRevision', 'kind', 'reason', 'confirm', 'items']);
  identifier(input.workflowId);
  if (input.confirm !== true || !validRevision(input.eligibilityRevision) || !['role', 'eligibility'].includes(input.kind)
    || !Array.isArray(input.items) || input.items.length < 1 || input.items.length > 25) fail(400, 'Confirm one captured page of 1–25 access grants');
  const items = input.items.map(item => {
    exact(item, ['id', 'version']); identifier(item.id);
    if (typeof item.version !== 'string' || !/^[a-f0-9]{64}$/u.test(item.version)) fail(400, 'Exact captured access version required');
    return { id: item.id, version: item.version };
  });
  if (new Set(items.map(item => item.id)).size !== items.length) fail(400, 'Duplicate offboarding access grant');
  return { workflowId: input.workflowId, eligibilityRevision: input.eligibilityRevision, kind: input.kind, reason: text(input.reason, 10, 500), confirm: true, items };
}
function offboardingEtag(job) {
  identifier(job.id); if (!validRevision(job.revision)) fail(503, 'Offboarding workflow version unavailable');
  return `"company-offboarding-${job.id}-${job.revision}"`;
}
function offboardingVersion(id, expected) {
  identifier(id); if (expected === undefined) fail(428, 'Exact offboarding If-Match required');
  const match = typeof expected === 'string' && /^"company-offboarding-([a-f0-9-]{36})-([1-9][0-9]{0,18})"$/u.exec(expected);
  if (!match || match[1] !== id || !validRevision(match[2])) fail(412, 'Offboarding workflow version changed'); return match[2];
}
function poolEtag(pool) { identifier(pool.id); if (!validRevision(pool.revision)) fail(503, 'Company pool revision unavailable'); return `"company-pool-${pool.id}-${pool.revision}"`; }
function expectedVersion(id, expected) {
  identifier(id); if (expected === undefined) fail(428, 'Exact company pool If-Match required');
  const match = typeof expected === 'string' && /^"company-pool-([a-f0-9-]{36})-([1-9][0-9]{0,18})"$/u.exec(expected);
  if (!match || match[1] !== id || !validRevision(match[2])) fail(412, 'Company pool version changed'); return match[2];
}
function pagination(input, search = false) {
  if (!input || typeof input !== 'object' || Object.keys(input).some(key => !['page', 'limit', ...(search ? ['search'] : [])].includes(key))) fail(400, 'Unsupported company license selectors');
  const integer = (value, fallback, maximum) => { if (value === undefined) return fallback; if (typeof value !== 'string' || !/^[1-9][0-9]*$/u.test(value) || Number(value) > maximum) fail(400, 'Invalid company license page'); return Number(value); };
  return { page: integer(input.page, 1, 1000000), limit: integer(input.limit, 25, 100), search: search ? text(input.search === undefined ? '' : input.search, 0, 160) : '' };
}
module.exports = { COMPANY_LICENSE_PERMISSIONS, exact, text, identifier, poolValues, poolUpdateValues, assignmentValues, returnValues, offboardingIntent, offboardingContinuation, groupCleanupQuery, groupCleanupValues, accessCleanupCapabilitiesQuery, accessCleanupQuery, accessCleanupValues, offboardingEtag, offboardingVersion, poolEtag, expectedVersion, pagination };
