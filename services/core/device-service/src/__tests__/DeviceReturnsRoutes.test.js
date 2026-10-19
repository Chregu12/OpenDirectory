'use strict';

jest.mock('jose', () => ({ createRemoteJWKSet: jest.fn(() => ({})), jwtVerify: jest.fn() }));
jest.mock('../../../../../packages/oidc-access-state', () => ({ createAccessStateClient: jest.fn(() => jest.fn(async () => {})) }));
const request = require('supertest');
const { jwtVerify } = require('jose');
const { createInventoryApp } = require('../inventoryServer');
const { DeviceReturns } = require('../DeviceReturns');
const { randomUUID } = require('node:crypto');
let app; let returns; let user; let requestId; let userId; let workflowId; let dto;
beforeEach(() => {
  requestId = randomUUID(); userId = randomUUID(); workflowId = randomUUID(); user = { actor_type: 'user', token_use: 'access' }; jwtVerify.mockResolvedValue({ payload: user });
  dto = { id: requestId, revision: '1', currentDeviceRevision: '9007199254740993' };
  returns = Object.fromEntries(['capabilities','list','get','history','decide','offboardingCapabilities','offboardingList','offboardingHistory','request'].map(method => [method, jest.fn(async () => ({}))]));
  app = createInventoryApp({ db: {}, inventory: {}, returns });
});
function get(url) { return request(app).get(url).set('Authorization', 'Bearer original'); }
test.each([
  ['/api/devices/returns/capabilities','capabilities'], ['/api/devices/returns','list'], ['/api/devices/returns/ID','get'], ['/api/devices/returns/ID/history','history'],
])('GET %s reaches only its dedicated receiver', async (path, method) => {
  returns[method].mockResolvedValue(method === 'get' ? dto : { actual: method }); const response = await get(path.replace('ID', requestId)); expect(response.status).toBe(200); expect(returns[method]).toHaveBeenCalledTimes(1);
  if (method === 'get') expect(response.headers.etag).toBe(`"device-return-${requestId}-1-9007199254740993"`);
});
test.each(['capabilities','get'])('%s rejects uncontracted query before reading authority', async method => {
  const path = method === 'get' ? `/api/devices/returns/${requestId}` : '/api/devices/returns/capabilities'; expect((await get(path + '?tenant=foreign')).status).toBe(400); expect(returns[method]).not.toHaveBeenCalled();
});
test.each([['/capabilities','offboardingCapabilities'],['','offboardingList'],['/history','offboardingHistory']])('offboarding %s passes only original user/workflow query and human', async (suffix, method) => {
  const response = await get(`/api/devices/users/${userId}/offboarding-returns${suffix}?workflowId=${workflowId}`); expect(response.status).toBe(200);
  expect(returns[method]).toHaveBeenCalledWith(userId, { workflowId }, user, 'Bearer original');
});
test('decision passes exact original If-Match, human bearer and correlation without retry', async () => {
  returns.decide.mockResolvedValue({ request: dto, outcome: 'returned' }); const expected = `"device-return-${requestId}-1-2"`; const body = { action: 'returned', reason: 'Received physical device', confirm: true };
  const response = await request(app).post(`/api/devices/returns/${requestId}/decision`).set('Authorization','Bearer original').set('If-Match', expected).send(body);
  expect(response.status).toBe(200); expect(response.headers.etag).toBe(`"device-return-${requestId}-1-9007199254740993"`); expect(returns.decide).toHaveBeenCalledTimes(1);
  expect(returns.decide).toHaveBeenCalledWith(requestId, body, expected, user, 'Bearer original', response.headers['x-correlation-id']);
});
test.each([['requested',200],['already_requested',200],['unconfirmed',207],['not_attempted',207]])('child status %s returns actual HTTP %i', async (status, code) => {
  returns.request.mockResolvedValue({ results: [{ status }] }); const response = await request(app).post(`/api/devices/users/${userId}/offboarding-returns`).set('Authorization','Bearer original').send({ workflowId }); expect(response.status).toBe(code); expect(returns.request).toHaveBeenCalledTimes(1);
});
test('decision never forwards query parameters into the kernel', async () => {
  const response = await request(app).post(`/api/devices/returns/${requestId}/decision?force=true`).set('Authorization','Bearer original').send({}); expect(response.status).toBe(400); expect(returns.decide).not.toHaveBeenCalled();
});
test('GET emptyarray body is rejected instead of treated as no body', async () => {
  const response = await get('/api/devices/returns').send([]); expect(response.status).toBe(400); expect(returns.list).not.toHaveBeenCalled();
});
test('serviceaccounts and alternativecredentials never reach returns', async () => {
  jwtVerify.mockResolvedValueOnce({ payload: { actor_type:'application',token_use:'access' } }); expect((await get('/api/devices/returns')).status).toBe(403);
  expect((await request(app).get('/api/devices/returns').set('X-API-Key','alternate')).status).toBe(401); expect(returns.list).not.toHaveBeenCalled();
});
test('returns default derives only the trusted existing inventory origin', () => {
  const inventory = { authority: { endpoint: new URL('https://canonical.identity.test/api/identity/device-inventory') } };
  const service = new DeviceReturns({}, { inventory }); expect(service.authority.endpoint.href).toBe('https://canonical.identity.test/api/identity/device-offboarding'); expect(service.inventory).toBe(inventory);
});
test('history exposes the stored event version separately from the envelope schema version', async () => {
  const source = { actorUserId: randomUUID(), tenant: { id: randomUUID() } }; const eventId = randomUUID(); const deviceId = randomUUID(); const assignmentId = randomUUID(); const correlationId = randomUUID();
  const createdAt = new Date('2026-10-19T12:00:00.000Z'); const after = { revision: '1', status: 'requested' };
  const client = { query: jest.fn().mockResolvedValueOnce({ rows: [{ count: '1' }] }).mockResolvedValueOnce({ rows: [{ id: eventId, tenant_id: source.tenant.id, request_id: requestId, device_id: deviceId, assignment_id: assignmentId,
    type: 'device.return.requested', version: 1, actor_user_id: source.actorUserId, correlation_id: correlationId, created_at: createdAt, before_state: null, after_state: after, inventory_operation_id: null, reason: 'Collect original laptop' }] }) };
  const service = new DeviceReturns({ transaction: operation => operation(client) }, { inventory: {}, authority: {} });
  jest.spyOn(service, 'initial').mockResolvedValue(source); jest.spyOn(service, 'receiving').mockResolvedValue(); jest.spyOn(service, 'readTask').mockResolvedValue(); jest.spyOn(service, 'checkpoint').mockResolvedValue();
  expect(await service.history(requestId, {}, user, 'Bearer original')).toEqual({ schemaVersion: 1, actorUserId: source.actorUserId, tenantId: source.tenant.id, requestId,
    events: [{ id: eventId, tenantId: source.tenant.id, requestId, deviceId, assignmentId, type: 'device.return.requested', version: 1, actorUserId: source.actorUserId, correlationId, createdAt: createdAt.toISOString(), before: null, after,
      inventoryOperationId: null, reason: 'Collect original laptop', deliveryStatus: 'pending' }], total: 1, page: 1, limit: 25 });
});
