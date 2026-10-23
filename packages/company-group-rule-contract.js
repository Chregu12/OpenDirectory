'use strict';
const { exact, identifier, text } = require('./company-license-contract');
const { validRevision } = require('./identity-authorization-contract');
function fail(status, message) { throw Object.assign(new Error(message), { status }); }
const ATTRIBUTES = Object.freeze(['department', 'title', 'email', 'username', 'displayName']);
const OPERATORS = Object.freeze(['equals', 'startsWith', 'endsWith']);
function ids(values, maximum) {
  if (!Array.isArray(values) || values.length > maximum || new Set(values).size !== values.length) fail(400, 'Bounded unique canonical group-rule references required');
  values.forEach(identifier); return [...values].sort();
}
function draft(input) {
  exact(input, ['dynamic', 'childGroupIds', 'excludedUserIds']);
  let dynamic = null;
  if (input.dynamic !== null) {
    exact(input.dynamic, ['all']);
    if (!Array.isArray(input.dynamic.all) || !input.dynamic.all.length || input.dynamic.all.length > 8) fail(400, 'Use one to eight bounded dynamic conditions');
    dynamic = { all: input.dynamic.all.map(condition => {
      exact(condition, ['attribute', 'operator', 'value']);
      if (!ATTRIBUTES.includes(condition.attribute) || !OPERATORS.includes(condition.operator)) fail(400, 'Supported dynamic group attribute and comparison required');
      return { attribute: condition.attribute, operator: condition.operator, value: text(condition.value, 1, 160) };
    }) };
    if (new Set(dynamic.all.map(value => JSON.stringify(value))).size !== dynamic.all.length) fail(400, 'Duplicate dynamic conditions');
  }
  const childGroupIds = ids(input.childGroupIds, 25); const excludedUserIds = ids(input.excludedUserIds, 10000);
  if (!dynamic && !childGroupIds.length) fail(400, 'Configure a dynamic condition or at least one child group');
  return { dynamic, childGroupIds, excludedUserIds };
}
function command(input) {
  exact(input, ['draft', 'enabled', 'reason', 'confirm']);
  if (typeof input.enabled !== 'boolean' || input.confirm !== true) fail(400, 'Explicit group-rule effect confirmation required');
  return { draft: draft(input.draft), enabled: input.enabled, reason: text(input.reason, 10, 500), confirm: true };
}
function etag(groupId, revision) {
  identifier(groupId); if (revision !== null && !validRevision(revision)) fail(503, 'Group-rule revision unavailable');
  return `"group-rule-${groupId}-${revision === null ? 'absent' : revision}"`;
}
function expected(groupId, value) {
  if (value === undefined) fail(428, 'Captured group-rule If-Match required');
  if (value === etag(groupId, null)) return null;
  const match = typeof value === 'string' && /^"group-rule-([a-f0-9-]{36})-([1-9][0-9]{0,18})"$/.exec(value);
  if (!match || match[1] !== groupId || !validRevision(match[2]) || etag(groupId, match[2]) !== value) fail(400, 'One exact strong group-rule If-Match required'); return match[2];
}
module.exports = { ATTRIBUTES, OPERATORS, draft, command, etag, expected, fail };
