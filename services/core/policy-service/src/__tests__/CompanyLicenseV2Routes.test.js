'use strict';

const { randomUUID } = require('node:crypto');
const express = require('express');
const request = require('supertest');
const { companyLicenseV2Routes } = require('../licenses/companyV2Routes');
let app; let store; let offboarding; let user;
const base = '/api/licenses/company/v2';
const bearer = 'Bearer original.company.source-aware';
const methods = names => Object.fromEntries(names.map(name => [name, jest.fn(async () => ({}))]));
beforeEach(() => {
  user = { actor_type: 'user', identity_authorization: { userId: randomUUID() } };
  store = methods(['capabilities', 'assignments', 'assignmentPreview', 'assign', 'revoke', 'returnPreview', 'returnLicenses']);
  offboarding = methods(['capabilities', 'list', 'get', 'history', 'create', 'continue', 'preview']);
  app = express(); app.use(express.json()); app.use((req, _res, next) => { req.user = user; next(); }); app.use(base, companyLicenseV2Routes(store, offboarding));
});
test.each([
  ['/capabilities', 'capabilities'], ['/pools/POOL/assignments', 'assignments'], ['/users/USER/license-returns', 'returnPreview'],
])('GET %s preserves the original source-aware request without V1 substitution', async (path, method) => {
  const response = await request(app).get(base + path).set('Authorization', bearer);
  expect(response.status).toBe(200); expect(response.headers['cache-control']).toBe('no-store'); expect(store[method]).toHaveBeenCalledTimes(1);
  expect(store[method].mock.calls[0]).toContain(user); expect(store[method].mock.calls[0]).toContain(bearer); expect(Object.values(offboarding).every(operation => operation.mock.calls.length === 0)).toBe(true);
});
test.each([
  ['/offboarding-workflows/capabilities', 'capabilities'], ['/offboarding-workflows', 'list'], ['/offboarding-workflows/ID/history', 'history'], ['/users/USER/offboarding-preview', 'preview'],
])('GET %s uses the negative V2 workflow receiver', async (path, method) => {
  expect((await request(app).get(base + path).set('Authorization', bearer)).status).toBe(200);
  expect(offboarding[method]).toHaveBeenCalledTimes(1); expect(offboarding[method].mock.calls[0]).toContain(user); expect(offboarding[method].mock.calls[0]).toContain(bearer);
});
test('workflow detail exposes the actual returned version, including a revision above JS safe integer', async () => {
  const workflow = { id: randomUUID(), revision: '9007199254740993' }; offboarding.get.mockResolvedValue({ workflow });
  const response = await request(app).get(base + '/offboarding-workflows/' + workflow.id).set('Authorization', bearer);
  expect(response.status).toBe(200); expect(response.headers.etag).toBe(`"company-offboarding-${workflow.id}-${workflow.revision}"`);
});
test('explicit read-only recipient preview neither allocates nor fabricates absence from a paginated list', async () => {
  const poolId = randomUUID(); const body = { userId: randomUUID() };
  const response = await request(app).post(base + '/pools/' + poolId + '/assignment-preview').set('Authorization', bearer).send(body);
  expect(response.status).toBe(200); expect(store.assignmentPreview).toHaveBeenCalledWith(poolId, body, user, bearer); expect(store.assign).not.toHaveBeenCalled();
});
test.each(['applied', 'already_applied'])('manual assignment %s is an explicit immutable receipt, not a pool response', async outcome => {
  const poolId = randomUUID(); const operationId = randomUUID(); const tag = `"company-pool-${poolId}-4"`; const body = { captured: 'original intent' };
  store.assign.mockResolvedValue({ outcome, seatAllocated: false, effectiveAssignmentRetained: true });
  const response = await request(app).post(base + '/pools/' + poolId + '/assignments').set('Idempotency-Key', operationId).set('If-Match', tag).set('Authorization', bearer).send(body);
  expect(response.status).toBe(outcome === 'applied' ? 201 : 200); expect(response.body.seatAllocated).toBe(false); expect(response.headers.etag || '').not.toMatch(/company-pool-/);
  expect(store.assign).toHaveBeenCalledWith(poolId, body, tag, operationId, user, bearer, response.headers['x-correlation-id']);
});
test('manual source removal forwards the captured projection without claiming a retained Blueprint seat was released', async () => {
  const poolId = randomUUID(); const projectionId = randomUUID(); const operationId = randomUUID(); const tag = `"company-pool-${poolId}-5"`;
  const body = { sources: [{ sourceType: 'direct', sourceId: 'direct', grantId: randomUUID() }], confirm: true };
  store.revoke.mockResolvedValue({ sourceRemoved: true, seatReleased: false, effectiveAssignmentRetained: true });
  const response = await request(app).post(base + '/pools/' + poolId + '/assignments/' + projectionId + '/revoke').set('Idempotency-Key', operationId).set('If-Match', tag).set('Authorization', bearer).send(body);
  expect(response.status).toBe(200); expect(response.body).toEqual({ sourceRemoved: true, seatReleased: false, effectiveAssignmentRetained: true });
  expect(store.revoke).toHaveBeenCalledWith(poolId, projectionId, body, tag, operationId, user, bearer, response.headers['x-correlation-id']);
});
test('negative returns preserve the exact source manifest and original operation key', async () => {
  const userId = randomUUID(); const operationId = randomUUID(); const body = { workflowId: randomUUID(), assignments: [], bindings: [{ id: randomUUID(), revision: '1' }] };
  const response = await request(app).post(base + '/users/' + userId + '/license-returns').set('Idempotency-Key', operationId).set('Authorization', bearer).send(body);
  expect(response.status).toBe(200); expect(store.returnLicenses).toHaveBeenCalledWith(userId, body, operationId, user, bearer, response.headers['x-correlation-id']);
});
test.each([true, false])('workflow creation created=%s returns the durable workflow, not a fresh account operation', async created => {
  const workflow = { id: randomUUID(), revision: '3' }; const body = { workflowId: workflow.id }; const operationId = randomUUID(); offboarding.create.mockResolvedValue({ created, result: { workflow } });
  const response = await request(app).post(base + '/offboarding-workflows').set('Idempotency-Key', operationId).set('Authorization', bearer).send(body);
  expect(response.status).toBe(created ? 201 : 200); expect(response.body).toEqual({ workflow }); expect(offboarding.create).toHaveBeenCalledWith(body, operationId, user, bearer);
});
test('continuation forwards original body, ETag and key without recapturing sources', async () => {
  const id = randomUUID(); const operationId = randomUUID(); const tag = `"company-offboarding-${id}-3"`; const body = { assignments: [], bindings: [] }; offboarding.continue.mockResolvedValue({ workflow: { id, revision: '4' } });
  const response = await request(app).post(base + '/offboarding-workflows/' + id + '/continue').set('Idempotency-Key', operationId).set('If-Match', tag).set('Authorization', bearer).send(body);
  expect(response.status).toBe(200); expect(offboarding.continue).toHaveBeenCalledWith(id, body, tag, operationId, user, bearer);
});
test.each([undefined, '', '*', 'alias', 'A'.repeat(36)])('invalid key %s never enters any V2 write', async operationId => {
  for (const path of ['/pools/POOL/assignments', '/pools/POOL/assignments/PROJECTION/revoke', '/users/USER/license-returns', '/offboarding-workflows', '/offboarding-workflows/ID/continue']) {
    const pending = request(app).post(base + path).send({}); if (operationId !== undefined) pending.set('Idempotency-Key', operationId); expect((await pending).status).toBe(400);
  }
  expect([...Object.values(store), ...Object.values(offboarding)].every(operation => operation.mock.calls.length === 0)).toBe(true);
});
test.each([{}, [], { userId: randomUUID() }])('GET body %j is rejected before any source-aware read', async body => {
  expect((await request(app).get(base + '/capabilities').send(body)).status).toBe(400); expect(store.capabilities).not.toHaveBeenCalled();
});
test.each(['', 'forged'])('API key presence %s cannot add authority', async key => {
  expect((await request(app).get(base + '/capabilities').set('X-API-Key', key)).status).toBe(400); expect(store.capabilities).not.toHaveBeenCalled();
});
test.each(['head', 'put', 'patch', 'delete'])('method %s has no implicit V2 authority', async method => {
  expect((await request(app)[method](base + '/capabilities')).status).toBe(404); expect(store.capabilities).not.toHaveBeenCalled();
});
test.each(['/capabilities', '/offboarding-workflows/capabilities', '/offboarding-workflows/ID', '/users/USER/offboarding-preview'])('selectors on %s are not hidden tenant or target overrides', async path => {
  expect((await request(app).get(base + path + '?tenantId=forged')).status).toBe(400);
  expect([...Object.values(store), ...Object.values(offboarding)].every(operation => operation.mock.calls.length === 0)).toBe(true);
});
test('mutation query selectors cannot reach a domain receiver', async () => {
  expect((await request(app).post(base + '/offboarding-workflows?tenantId=forged').set('Idempotency-Key', randomUUID()).send({})).status).toBe(400); expect(offboarding.create).not.toHaveBeenCalled();
});
test.each([400, 401, 403, 404, 409, 412, 428])('actual source-aware denial %s never falls back to V1', async status => {
  store.assignments.mockRejectedValue(Object.assign(new Error('Explicit denial'), { status })); const response = await request(app).get(base + '/pools/POOL/assignments');
  expect(response.status).toBe(status); expect(response.body.correlationId).toBe(response.headers['x-correlation-id']);
});
test('internal error details stay unavailable rather than disclosing proof or SQL', async () => {
  store.assignments.mockRejectedValue(new Error('SQL token secret')); const response = await request(app).get(base + '/pools/POOL/assignments');
  expect(response.status).toBe(503); expect(JSON.stringify(response.body)).not.toMatch(/SQL|token|secret/);
});
