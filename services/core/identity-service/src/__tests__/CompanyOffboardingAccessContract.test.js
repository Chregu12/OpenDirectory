'use strict';

const { randomUUID } = require('node:crypto');
const { accessCleanupCapabilitiesQuery, accessCleanupQuery, accessCleanupValues } = require('../../../../../packages/company-license-contract');
const workflowId = randomUUID();
const reason = 'Confirmed exact employee offboarding access cleanup';
const item = () => ({ id: randomUUID(), version: 'a'.repeat(64) });
const input = () => ({ workflowId, eligibilityRevision: '9223372036854775807', kind: 'role', reason, confirm: true, items: [item()] });

test('capability lookup accepts only the exact original canonical workflow selector', () => {
  expect(accessCleanupCapabilitiesQuery({ workflowId })).toEqual({ workflowId });
  for (const query of [null, [], {}, { workflowId, kind: 'role' }, { workflowId: '*' }, { workflowId, tenantId: randomUUID() }]) expect(() => accessCleanupCapabilitiesQuery(query)).toThrow();
});
test.each(['role', 'eligibility'])('access pagination captures only explicit %s kind and fixed 25-row pages', kind => {
  expect(accessCleanupQuery({ workflowId, kind })).toEqual({ workflowId, kind, page: 1, limit: 25 });
  expect(accessCleanupQuery({ workflowId, kind, page: '1000000', limit: '25' })).toEqual({ workflowId, kind, page: 1000000, limit: 25 });
});
test.each([null, [], {}, { workflowId }, { workflowId, kind: 'roles' }, { workflowId, kind: ['role'] }, { workflowId, kind: 'role', page: 1 },
  { workflowId, kind: 'role', limit: 25 }, { workflowId, kind: 'role', limit: '24' }, { workflowId, kind: 'role', page: '01' },
  { workflowId, kind: 'role', page: '1000001' }, { workflowId, kind: 'role', permission: 'admin' }])('rejects unsupported access selectors: %j', query => {
  expect(() => accessCleanupQuery(query)).toThrow();
});
test.each(['role', 'eligibility'])('confirmed %s manifests retain original row IDs, hashes and bigint epoch', kind => {
  const values = { ...input(), kind, items: Array.from({ length: 25 }, item) };
  expect(accessCleanupValues({ ...values, reason: '  ' + reason + '  ' })).toEqual(values);
});
test.each([
  body => ({ ...body, tenantId: randomUUID() }), body => ({ ...body, checkpointId: randomUUID() }), body => ({ ...body, confirm: false }),
  body => ({ ...body, reason: 'short' }), body => ({ ...body, reason: reason + '\n' }), body => ({ ...body, reason: 'x'.repeat(501) }),
  body => ({ ...body, eligibilityRevision: 1 }), body => ({ ...body, eligibilityRevision: '0' }), body => ({ ...body, eligibilityRevision: '9223372036854775808' }),
  body => ({ ...body, kind: 'all' }), body => ({ ...body, items: [] }), body => ({ ...body, items: Array.from({ length: 26 }, item) }),
  body => ({ ...body, items: [body.items[0], body.items[0]] }), body => ({ ...body, items: [{ ...item(), version: 'A'.repeat(64) }] }),
  body => ({ ...body, items: [{ ...item(), version: 'a'.repeat(63) }] }), body => ({ ...body, items: [{ ...item(), version: 1 }] }),
  body => ({ ...body, items: [{ ...item(), id: 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA' }] }), body => ({ ...body, items: [{ ...item(), role: 'admin' }] }),
])('invalid captured access confirmations fail closed (%#)', transform => {
  expect(() => accessCleanupValues(transform(input()))).toThrow();
});
test('OpenAPI describes separate actual duties, no Owner promotion, exact hashes and real child checkpoints', () => {
  const document = require('../../scripts/company-offboarding-access-openapi').companyOffboardingAccessOpenApi();
  const base = '/api/users/{id}/company-offboarding-access'; const path = document.paths[base];
  expect(document.paths[base + '/capabilities'].get.parameters.map(parameter => parameter.name)).toEqual(['id', 'workflowId']);
  expect(path.get.parameters.map(parameter => parameter.name)).toEqual(['id', 'workflowId', 'kind', 'page', 'limit']);
  expect(path.post.requestBody.content['application/json'].schema.required).toEqual(['workflowId', 'eligibilityRevision', 'kind', 'reason', 'confirm', 'items']);
  expect(path.post.requestBody.content['application/json'].schema.properties.items.maxItems).toBe(25);
  expect(path.post.description).toContain('DirectoryRoles.revoke'); expect(path.post.description).toContain('PrivilegedActivation.revokeEligibility');
  expect(path.post.description).toContain('Protected grants additionally require actual canonical admin');
  expect(document.components.schemas.CompanyOffboardingAccessPreview.properties.items.items.properties.version.pattern).toBe('^[a-f0-9]{64}$');
  expect(document.components.schemas.CompanyOffboardingAccessHistory.properties.receipts.items.properties.deliveryStatus.const).toBe('pending');
  expect(path.post.responses[207].content['application/json'].schema.$ref).toBe('#/components/schemas/CompanyOffboardingAccessResult');
});
