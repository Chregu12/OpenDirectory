'use strict';

const { randomUUID } = require('node:crypto');
const { returnListQuery, offboardingReturnQuery, offboardingReturnCapabilityQuery, deviceOffboardingValues,
  offboardingReturnValues, returnDecisionValues, deviceReturnEtag, validateDeviceReturnEtag } = require('../../../../../packages/device-inventory-contract');
const workflowId = randomUUID(); const reason = 'Explicit actual original device return request';
const item = () => ({ deviceId: randomUUID(), deviceRevision: '9223372036854775807', assignmentId: randomUUID(), requestId: randomUUID() });
const input = () => ({ workflowId, eligibilityRevision: '9007199254740993', reason, confirm: true, items: [item()] });
test('return pagination uses real fixed pages and explicit optional operational status', () => {
  expect(returnListQuery({})).toEqual({ page: 1, limit: 25, status: null });
  for (const status of ['requested', 'returned', 'cancelled', 'assignment_changed']) expect(returnListQuery({ page: '1000000', limit: '25', status })).toEqual({ page: 1000000, limit: 25, status });
  expect(offboardingReturnQuery({ workflowId })).toEqual({ workflowId, page: 1, limit: 25 }); expect(offboardingReturnCapabilityQuery({ workflowId })).toEqual({ workflowId });
});
test.each([null, [], { page: 1 }, { page: '0' }, { page: '01' }, { page: '1000001' }, { limit: '26' }, { status: 'all' }, { tenantId: randomUUID() }])('operational selectors fail closed: %j', query => {
  expect(() => returnListQuery(query)).toThrow();
});
test('private source accepts only the canonical original employee and account workflow selectors', () => {
  const body = { workflowId, userId: randomUUID() }; expect(deviceOffboardingValues(body)).toEqual(body);
  for (const query of [{ ...body, tenantId: randomUUID() }, { workflowId }, null, { ...body, userId: '*' }]) expect(() => deviceOffboardingValues(query)).toThrow();
});
test('confirmed manifests retain exact captured device versions and stable request UUIDs', () => {
  const body = { ...input(), items: Array.from({ length: 25 }, item) };
  expect(offboardingReturnValues({ ...body, reason: '  ' + reason + '  ' })).toEqual(body);
});
test.each([
  body => ({ ...body, confirm: false }), body => ({ ...body, actorUserId: randomUUID() }), body => ({ ...body, reason: 'short' }),
  body => ({ ...body, reason: reason + '\n' }), body => ({ ...body, reason: 'x'.repeat(501) }), body => ({ ...body, eligibilityRevision: 1 }),
  body => ({ ...body, eligibilityRevision: '9223372036854775808' }), body => ({ ...body, items: [] }), body => ({ ...body, items: Array.from({ length: 26 }, item) }),
  body => ({ ...body, items: [{ ...item(), deviceRevision: '01' }] }), body => ({ ...body, items: [{ ...item(), requestId: 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA' }] }),
  body => ({ ...body, items: [{ ...item(), source: {} }] }),
  ...['deviceId', 'assignmentId', 'requestId'].map(field => body => ({ ...body, items: [body.items[0], { ...item(), [field]: body.items[0][field] }] })),
])('captured device manifests reject changed or caller-owned data (%#)', transform => {
  expect(() => offboardingReturnValues(transform(input()))).toThrow();
});
test.each(['returned', 'cancelled'])('operational %s decisions require their own explicit reason and confirmation', action => {
  expect(returnDecisionValues({ action, reason: '  ' + reason + '  ', confirm: true })).toEqual({ action, reason, confirm: true });
  for (const change of [{ action: 'wipe' }, { confirm: false }, { reason: 'short' }, { deviceId: randomUUID() }]) expect(() => returnDecisionValues({ action, reason, confirm: true, ...change })).toThrow();
});
test('strong return ETags bind both the request and the actual current device version without rounding', () => {
  const id = randomUUID(); const tag = deviceReturnEtag({ id, revision: '9007199254740993', currentDeviceRevision: '9223372036854775807' });
  expect(tag).toBe(`"device-return-${id}-9007199254740993-9223372036854775807"`);
  expect(validateDeviceReturnEtag(tag)).toEqual({ id, revision: '9007199254740993', deviceRevision: '9223372036854775807' });
  for (const value of [undefined, null, '']) expect(() => validateDeviceReturnEtag(value)).toThrow('device_return_etag_required');
  for (const value of ['*', 'W/' + tag, tag + ', ' + tag, tag.replace('9007199254740993', '01'), tag.replace('9223372036854775807', '9223372036854775808')]) expect(() => validateDeviceReturnEtag(value)).toThrow('invalid_device_return_etag');
});
test('OpenAPI keeps request, physical confirmation and original-account provenance separate', () => {
  const document = require('../../scripts/device-returns-openapi').deviceReturnsOpenApi(); const schemas = document.components.schemas;
  expect(schemas.DeviceReturnRequest.required).toHaveLength(22); expect(schemas.DeviceOffboardingAuthoritySource.required).toHaveLength(13);
  expect(schemas.DeviceReturnEvent.properties.version.const).toBe(1);
  expect(schemas.DeviceOffboardingAuthoritySource.properties.target.required).toEqual(['id', 'enabled', 'eligibilityRevision']);
  expect(schemas.DeviceReturnCapabilities.properties.permissions.const).toEqual(['devices.inventory.read', 'devices.inventory.create', 'devices.inventory.assign']);
  expect(document.paths['/api/devices/returns/{id}/decision'].post.parameters.map(parameter => parameter.name)).toEqual(['id', 'If-Match']);
  expect(document.paths['/api/devices/returns/{id}/decision'].post.requestBody.content['application/json'].schema.required).toEqual(['action', 'reason', 'confirm']);
  expect(document.paths['/api/devices/users/{userId}/offboarding-returns'].post.requestBody.content['application/json'].schema.properties.items.maxItems).toBe(25);
  expect(document.paths['/api/devices/users/{userId}/offboarding-returns'].post.responses[207]).toBeDefined();
});
