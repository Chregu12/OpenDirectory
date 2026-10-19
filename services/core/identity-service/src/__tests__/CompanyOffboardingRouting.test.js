'use strict';

const { randomUUID } = require('crypto');
jest.mock('../db', () => ({ isAvailable: () => true, pool: { end: jest.fn() } }));
jest.mock('../middleware/oidcAuth', () => ({ oidcAuth: () => (req, _res, next) => { req.user = { sub: 'roleless-owner', actor_type: 'user' }; next(); } }));
jest.mock('../CompanyOffboarding', () => ({ CompanyOffboarding: jest.fn() }));
jest.mock('@opendirectory/grpc-event-bus', () => ({ EventBusClient: jest.fn(() => ({ connect: jest.fn(), publish: jest.fn(async () => {}) })) }), { virtual: true });
const { CompanyOffboarding } = require('../CompanyOffboarding');
const receive = jest.fn(); CompanyOffboarding.mockImplementation(() => ({ receive }));
const app = require('../index');
const request = require('supertest');
const target = randomUUID(); const body = { workflowId: randomUUID(), expectedRevision: '9007199254740993', confirm: true };
beforeEach(() => { receive.mockReset(); });
test('exact POST reaches the company bridge for a roleless human and returns its exact no-store receipt', async () => {
  const receipt = { schemaVersion: 1, workflowId: body.workflowId, tenantId: randomUUID(), userId: target, actorUserId: randomUUID(), operationId: randomUUID(),
    action: 'disabled', beforeRevision: body.expectedRevision, afterRevision: '9007199254740994', beforeEligibilityRevision: '7', afterEligibilityRevision: '99',
    createdAt: new Date().toISOString(), deliveryStatus: 'pending' };
  receive.mockResolvedValue(receipt);
  const result = await request(app).post(`/api/users/${target}/company-offboarding`).set('Authorization', 'Bearer original').send(body);
  expect(result.status).toBe(200); expect(result.headers['cache-control']).toBe('no-store'); expect(result.body).toEqual(receipt);
  expect(receive).toHaveBeenCalledWith(target, body, { sub: 'roleless-owner', actor_type: 'user' }, 'Bearer original');
});
test.each([409, 412, 428, 401, 403, 404])('preserves bounded bridge rejection status %s', async status => {
  receive.mockRejectedValue(Object.assign(new Error('Rejected'), { status }));
  expect((await request(app).post(`/api/users/${target}/company-offboarding`).send(body)).status).toBe(status);
});
test('query and API-key selectors are rejected before the bridge', async () => {
  expect((await request(app).post(`/api/users/${target}/company-offboarding?tenantId=foreign`).send(body)).status).toBe(400);
  expect((await request(app).post(`/api/users/${target}/company-offboarding`).set('X-API-Key', 'irrelevant').send(body)).status).toBe(400);
  expect(receive).not.toHaveBeenCalled();
});
test('no alternate method or suffix reaches the bridge', async () => {
  expect((await request(app).put(`/api/users/${target}/company-offboarding`).send(body)).status).toBe(404);
  expect((await request(app).post(`/api/users/${target}/company-offboarding/extra`).send(body)).status).toBe(404);
  expect(receive).not.toHaveBeenCalled();
});
