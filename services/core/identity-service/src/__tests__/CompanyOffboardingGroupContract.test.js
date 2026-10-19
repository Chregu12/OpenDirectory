'use strict';

const { randomUUID } = require('node:crypto');
const { groupCleanupQuery, groupCleanupValues } = require('../../../../../packages/company-license-contract');
const workflowId = randomUUID();
const reason = 'Confirmed captured group cleanup for employee exit';
const member = () => ({ groupId: randomUUID(), groupRevision: '9007199254740993', membershipId: randomUUID() });
const input = () => ({ workflowId, eligibilityRevision: '9223372036854775807', reason, confirm: true, memberships: [member()] });

test('group cleanup pagination has one required canonical parent and fixed 25-row pages', () => {
  expect(groupCleanupQuery({ workflowId })).toEqual({ workflowId, page: 1, limit: 25 });
  expect(groupCleanupQuery({ workflowId, page: '1000000', limit: '25' })).toEqual({ workflowId, page: 1000000, limit: 25 });
});
test.each([{}, null, [], { workflowId: '*' }, { workflowId, tenantId: randomUUID() }, { workflowId, page: '0' }, { workflowId, page: '01' },
  { workflowId, page: '1000001' }, { workflowId, page: 1 }, { workflowId, limit: '24' }, { workflowId, limit: '26' }, { workflowId, limit: 25 }, { workflowId: [workflowId] }])('rejects unsupported group selectors before storage: %j', query => {
  expect(() => groupCleanupQuery(query)).toThrow();
});
test('normalized confirmations retain exact parent, negative generation and membership incarnations', () => {
  const values = input();
  expect(groupCleanupValues({ ...values, reason: '  ' + reason + '  ' })).toEqual(values);
  const members = Array.from({ length: 25 }, member);
  expect(groupCleanupValues({ ...values, memberships: members }).memberships).toEqual(members);
});
test('the group API documents explicit parent binding, captured-page confirmation and independent directory duties', () => {
  const document = require('../../scripts/company-offboarding-groups-openapi').companyOffboardingGroupsOpenApi();
  const path = document.paths['/api/users/{id}/company-offboarding-groups'];
  expect(path.get.parameters.map(parameter => parameter.name)).toEqual(['id', 'workflowId', 'page', 'limit']);
  expect(path.get.description).toContain('groups.read'); expect(path.post.description).toContain('groups.members.manage');
  expect(path.post.requestBody.content['application/json'].schema.required).toEqual(['workflowId', 'eligibilityRevision', 'reason', 'confirm', 'memberships']);
  expect(path.post.requestBody.content['application/json'].schema.properties.memberships.maxItems).toBe(25);
  expect(path.post.responses[207].content['application/json'].schema.$ref).toBe('#/components/schemas/CompanyOffboardingGroupsResult');
  expect(document.components.schemas.CompanyOffboardingGroupsHistory.properties.receipts.items.properties.deliveryStatus.const).toBe('pending');
  expect(document.components.schemas.CompanyOffboardingGroupsPreview.properties.companyOffboardingGroupsProtocol.const).toBe(1);
});
test.each([
  body => ({ ...body, tenantId: randomUUID() }), body => ({ ...body, confirm: false }), body => ({ ...body, reason: 'short' }),
  body => ({ ...body, reason: reason + '\n' }), body => ({ ...body, reason: 'x'.repeat(501) }),
  body => ({ ...body, eligibilityRevision: '0' }), body => ({ ...body, eligibilityRevision: 1 }), body => ({ ...body, eligibilityRevision: '9223372036854775808' }),
  body => ({ ...body, memberships: [] }), body => ({ ...body, memberships: Array.from({ length: 26 }, member) }),
  body => ({ ...body, memberships: [body.memberships[0], { ...member(), groupId: body.memberships[0].groupId }] }),
  body => ({ ...body, memberships: [body.memberships[0], { ...member(), membershipId: body.memberships[0].membershipId }] }),
  body => ({ ...body, memberships: [{ ...member(), groupRevision: '01' }] }), body => ({ ...body, memberships: [{ ...member(), groupRevision: 2 }] }),
  body => ({ ...body, memberships: [{ ...member(), groupRevision: '9223372036854775808' }] }),
  body => ({ ...body, memberships: [{ ...member(), groupId: 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA' }] }),
  body => ({ ...body, memberships: [{ ...member(), membershipId: '*' }] }), body => ({ ...body, memberships: [{ ...member(), grantId: randomUUID() }] }),
])('invalid captured group confirmations fail closed (%#)', transform => {
  expect(() => groupCleanupValues(transform(input()))).toThrow();
});
