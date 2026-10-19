'use strict';

const { randomUUID } = require('node:crypto');
const express = require('express');
const request = require('supertest');
const { companyBlueprintAssignmentRoutes } = require('../companyBlueprintAssignmentRoutes');
let app; let store; let user;
const base = '/api/company-blueprint-assignments';
const bearer = 'Bearer original.company.blueprint.assignment';
beforeEach(() => {
  user = { actor_type: 'user', identity_authorization: { userId: randomUUID() } };
  store = Object.fromEntries(['capabilities', 'list', 'get', 'effective', 'preview', 'removalPreview', 'change'].map(method => [method, jest.fn(async () => ({ outcome: 'applied' }))]));
  app = express(); app.use(express.json()); app.use((req, _res, next) => { req.user = user; next(); });
  app.use(base, companyBlueprintAssignmentRoutes({}, { store }));
});
test.each([
  ['/capabilities', 'capabilities'], ['', 'list'], ['/users/recipient/effective', 'effective'],
])('GET %s delegates only to the assignment receiver with the original human bearer', async (path, method) => {
  const response = await request(app).get(base + path).set('Authorization', bearer);
  expect(response.status).toBe(200); expect(response.headers['cache-control']).toBe('no-store'); expect(response.headers['x-correlation-id']).toMatch(/^[a-f0-9-]{36}$/);
  expect(store[method]).toHaveBeenCalledTimes(1); expect(store[method].mock.calls[0]).toContain(user); expect(store[method].mock.calls[0]).toContain(bearer);
  expect(Object.entries(store).filter(([name]) => name !== method).every(([, method]) => method.mock.calls.length === 0)).toBe(true);
});
test('binding detail returns the actual captured incarnation ETag without rounding its revision', async () => {
  const id = randomUUID(); const assignment = { id, revision: '9007199254740993' }; store.get.mockResolvedValue({ assignment });
  const response = await request(app).get(base + '/' + id).set('Authorization', bearer);
  expect(response.status).toBe(200); expect(response.headers.etag).toBe(`"company-blueprint-assignment-${id}-${assignment.revision}"`);
  expect(store.get).toHaveBeenCalledWith(id, user, bearer);
});
test('removal preview returns its original binding ETag without positive assignment admission or a mutation key', async () => {
  const id = randomUUID(); const assignment = { id, revision: '1' }; store.removalPreview.mockResolvedValue({ assignment, eligibilityRevision: '5', pools: [] });
  const response = await request(app).get(base + '/' + id + '/removal-preview').set('Authorization', bearer);
  expect(response.status).toBe(200); expect(response.headers.etag).toBe(`"company-blueprint-assignment-${id}-1"`);
  expect(store.removalPreview).toHaveBeenCalledWith(id, user, bearer); expect(store.preview).not.toHaveBeenCalled(); expect(store.change).not.toHaveBeenCalled();
});
test('preview is an explicit read-only POST to the own receiver, not an allocation command', async () => {
  const body = { userId: randomUUID(), blueprintId: randomUUID(), version: 1 };
  const response = await request(app).post(base + '/preview').set('Authorization', bearer).send(body);
  expect(response.status).toBe(200); expect(store.preview).toHaveBeenCalledWith(body, user, bearer); expect(store.change).not.toHaveBeenCalled();
});
test.each(['assigned', 'removed'])('%s forwards the exact original key, body, If-Match and correlation', async action => {
  const id = randomUUID(); const operationId = randomUUID(); const tag = `"company-blueprint-assignment-${id}-9007199254740993"`;
  const body = { userId: randomUUID(), eligibilityRevision: '5', pools: [], reason: 'Explicitly confirmed own assignment', confirm: true };
  const response = await request(app).post(base + (action === 'removed' ? '/' + id + '/remove' : '')).set('Authorization', bearer).set('Idempotency-Key', operationId).set('If-Match', tag).send(body);
  expect(response.status).toBe(action === 'assigned' ? 201 : 200);
  expect(store.change).toHaveBeenCalledWith(action, action === 'removed' ? id : undefined, body, tag, operationId, user, bearer, response.headers['x-correlation-id']);
});
test('recovery returns a historical 200 receipt and does not claim a new allocation', async () => {
  store.change.mockResolvedValue({ outcome: 'already_applied' });
  const response = await request(app).post(base).set('Idempotency-Key', randomUUID()).send({}); expect(response.status).toBe(200); expect(response.body.outcome).toBe('already_applied');
});
test.each([undefined, '', 'alias', 'A'.repeat(36), '*'])('invalid Idempotency-Key %s cannot enter a mutation', async operationId => {
  const pending = request(app).post(base).send({}); if (operationId !== undefined) pending.set('Idempotency-Key', operationId);
  expect((await pending).status).toBe(400); expect(store.change).not.toHaveBeenCalled();
});
test.each([{}, [], { tenantId: randomUUID() }])('a supplied GET body %j cannot enter any receiver', async body => {
  expect((await request(app).get(base + '/capabilities').send(body)).status).toBe(400); expect(store.capabilities).not.toHaveBeenCalled();
});
test.each(['', 'forged'])('the presence of an API key %s never supplements human authority', async key => {
  expect((await request(app).get(base + '/capabilities').set('X-API-Key', key)).status).toBe(400); expect(store.capabilities).not.toHaveBeenCalled();
});
test.each(['/capabilities', '/binding', '/users/recipient/effective'])('unsupported selectors on %s cannot enter a receiver', async path => {
  expect((await request(app).get(base + path + '?tenantId=forged')).status).toBe(400); expect(Object.values(store).every(method => method.mock.calls.length === 0)).toBe(true);
});
test('paged binding list forwards selectors for bounded domain validation', async () => {
  expect((await request(app).get(base + '?userId=recipient&page=2&limit=25').set('Authorization', bearer)).status).toBe(200);
  expect(store.list).toHaveBeenCalledWith({ userId: 'recipient', page: '2', limit: '25' }, user, bearer);
});
test.each(['', '/preview', '/binding/remove'])('write selectors on %s cannot enter any receiver', async path => {
  expect((await request(app).post(base + path + '?tenantId=forged').set('Idempotency-Key', randomUUID()).send({})).status).toBe(400);
  expect(Object.values(store).every(method => method.mock.calls.length === 0)).toBe(true);
});
test.each(['head', 'put', 'patch', 'delete'])('unsupported %s does not gain implicit GET or write authority', async method => {
  expect((await request(app)[method](base)).status).toBe(404); expect(Object.values(store).every(operation => operation.mock.calls.length === 0)).toBe(true);
});
test.each([400, 401, 403, 404, 409, 412, 428])('explicit denial %s preserves the actual receiver status', async status => {
  store.list.mockRejectedValue(Object.assign(new Error('Explicit receiver denial'), { status }));
  const response = await request(app).get(base); expect(response.status).toBe(status); expect(response.body.correlationId).toBe(response.headers['x-correlation-id']);
});
test('unavailable source or storage never exposes an internal SQL payload', async () => {
  store.list.mockRejectedValue(new Error('SQL internal token secret')); const response = await request(app).get(base);
  expect(response.status).toBe(503); expect(JSON.stringify(response.body)).not.toMatch(/SQL|token|secret/); expect(response.body.correlationId).toBe(response.headers['x-correlation-id']);
});
