'use strict';

const { randomUUID } = require('node:crypto');
const { sources, manualValues, retirementValues, manualCommand } = require('../licenses/CompanyLicenseSourcesContract');
const { continuation } = require('../licenses/CompanyOffboardingV2');
const { poolEtag } = require('../../../../../packages/company-license-contract');

const userId = randomUUID(); const poolId = randomUUID(); const assignmentId = randomUUID();
const manual = { sourceType: 'direct', sourceId: 'direct', grantId: randomUUID() };
const blueprint = { sourceType: 'blueprint', sourceId: randomUUID(), grantId: randomUUID() };
const reason = 'Explicit immutable source manifest review';
const assign = { userId, eligibilityRevision: '9007199254740993', assignmentId: null, sources: [], reason, confirm: true };

test('a complete source manifest keeps exact separate origins and server grant incarnations', () => {
  expect(sources([blueprint, manual])).toEqual([blueprint, manual]);
  expect(manualValues('manual_assign', { ...assign, assignmentId, sources: [blueprint] }).eligibilityRevision).toBe('9007199254740993');
});
test.each([
  null, {}, [manual, manual], [{ ...manual, sourceId: blueprint.sourceId }], [{ ...blueprint, sourceId: 'direct' }],
  [{ ...manual, sourceType: 'group' }], [{ ...manual, tenantId: randomUUID() }], [{ ...manual, grantId: 'unknown' }],
  [manual, blueprint], [{ ...blueprint, sourceId: blueprint.sourceId.toUpperCase() }],
].map(value => ({ value })))('invalid or incomplete source manifests are rejected: %#', ({ value }) => {
  expect(() => sources(value)).toThrow();
});
test.each([
  { ...assign, confirm: false }, { ...assign, tenantId: randomUUID() }, { ...assign, assignmentId, sources: [] },
  { ...assign, sources: [blueprint] }, { ...assign, assignmentId, sources: [manual] }, { ...assign, eligibilityRevision: '9223372036854775808' },
  { ...assign, eligibilityRevision: 11 }, { ...assign, reason: 'short' },
])('manual assignment cannot infer authority or reuse an existing source: %#', value => {
  expect(() => manualValues('manual_assign', value)).toThrow();
});
test('manual removal explicitly captures all origins but targets exactly the manual grant', () => {
  const input = { userId, eligibilityRevision: '11', sources: [blueprint, manual], reason, confirm: true };
  const command = manualCommand('manual_revoke', poolId, assignmentId, input, poolEtag({ id: poolId, revision: '5' }), randomUUID(), randomUUID());
  expect(command.values).toEqual({ projectionId: assignmentId, grantId: manual.grantId, sources: [blueprint, manual] });
  expect(command.pools).toEqual([{ poolId, poolRevision: '5' }]); expect(command.assignmentId).toBeNull();
});
test.each([{ captured: [] }, { captured: [blueprint] }])('manual removal cannot remove a blueprint-only source: %#', ({ captured }) => {
  expect(() => manualValues('manual_revoke', { userId, eligibilityRevision: '11', sources: captured, reason, confirm: true })).toThrow();
});
test('zero-app bindings are independently capturable and require an original workflow', () => {
  const binding = { id: randomUUID(), revision: '1' };
  const value = { workflowId: randomUUID(), eligibilityRevision: '104', assignments: [], bindings: [binding], reason, confirm: true };
  expect(retirementValues(value).bindings).toEqual([binding]);
  expect(() => retirementValues({ ...value, workflowId: null })).toThrow();
});
test('a complete negative workflow accepts more than 25 pools without page truncation', () => {
  const assignments = Array.from({ length: 26 }, () => ({ poolId: randomUUID(), poolRevision: '2', assignmentId: randomUUID(), sources: [{ ...manual, grantId: randomUUID() }] }));
  const value = { workflowId: randomUUID(), eligibilityRevision: '104', assignments, bindings: [], reason, confirm: true };
  expect(retirementValues(value).assignments).toHaveLength(26);
  expect(() => retirementValues({ ...value, workflowId: null })).toThrow();
});
test('standalone negative returns cannot borrow app authority to remove blueprint sources', () => {
  const value = { workflowId: null, eligibilityRevision: '104', assignments: [{ poolId, poolRevision: '3', assignmentId, sources: [blueprint] }], bindings: [], reason, confirm: true };
  expect(() => retirementValues(value)).toThrow();
  expect(retirementValues({ ...value, assignments: [{ ...value.assignments[0], sources: [manual] }] }).workflowId).toBeNull();
});
test('continuation keeps every original source and binding identity with no captured anchor reinterpretation', () => {
  const value = { confirm: true, reason, userRevision: '17', assignments: [{ poolId, poolRevision: '3', assignmentId, sources: [blueprint, manual] }], bindings: [{ id: blueprint.sourceId, revision: '1' }] };
  expect(continuation(value)).toEqual(value);
  expect(() => continuation({ ...value, assignments: [{ ...value.assignments[0], grantId: manual.grantId }] })).toThrow();
  expect(() => continuation({ ...value, assignments: [...value.assignments, ...value.assignments] })).toThrow();
});
