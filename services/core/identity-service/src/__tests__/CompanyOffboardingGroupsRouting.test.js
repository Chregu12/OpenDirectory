'use strict';

const { randomUUID } = require('crypto');
jest.mock('../db', () => ({ isAvailable: () => true, pool: { end: jest.fn() } }));
jest.mock('../middleware/oidcAuth', () => ({ oidcAuth: () => (req, _res, next) => { req.user = { sub: 'roleless-owner', actor_type: 'user' }; next(); } }));
jest.mock('../CompanyOffboardingGroups', () => ({ CompanyOffboardingGroups: jest.fn() }));
jest.mock('@opendirectory/grpc-event-bus', () => ({ EventBusClient: jest.fn(() => ({ connect: jest.fn(), publish: jest.fn(async () => {}) })) }), { virtual: true });
const { CompanyOffboardingGroups } = require('../CompanyOffboardingGroups');
const preview = jest.fn(); const history = jest.fn(); const remove = jest.fn();
CompanyOffboardingGroups.mockImplementation(() => ({ preview, history, remove }));
const app = require('../index');
const request = require('supertest');
const target = randomUUID(); const workflowId = randomUUID(); const path = `/api/users/${target}/company-offboarding-groups`;
beforeEach(() => { preview.mockReset(); history.mockReset(); remove.mockReset(); });
test('exact GET preview and history pass only original selectors and bearer', async () => {
  for (const [suffix, method] of [['', preview], ['/history', history]]) {
    method.mockResolvedValue({ retained: true });
    const response = await request(app).get(path + suffix).query({ workflowId, page: '2', limit: '25' }).set('Authorization', 'Bearer original');
    expect(response.status).toBe(200); expect(response.headers['cache-control']).toBe('no-store');
    expect(method).toHaveBeenCalledWith(target, { workflowId, page: '2', limit: '25' }, { sub: 'roleless-owner', actor_type: 'user' }, 'Bearer original');
  }
});
test.each([['removed', 200], ['already_removed', 200], ['unconfirmed', 207]])('POST returns %s with HTTP %s', async (status, code) => {
  const result = { results: [{ status }] }; remove.mockResolvedValue(result);
  const response = await request(app).post(path).send({ workflowId }); expect(response.status).toBe(code); expect(response.body).toEqual(result); expect(response.headers['cache-control']).toBe('no-store');
});
test('query, GET body and API keys fail before the bridge', async () => {
  expect((await request(app).post(path).query({ workflowId }).send({})).status).toBe(400);
  expect((await request(app).get(path).query({ workflowId }).send({ userId: target })).status).toBe(400);
  expect((await request(app).get(path).query({ workflowId }).send([])).status).toBe(400);
  expect((await request(app).get(path).query({ workflowId }).set('X-API-Key', 'unused')).status).toBe(400);
  expect((await request(app).post(path).set('X-API-Key', 'unused').send({})).status).toBe(400);
  expect(remove).not.toHaveBeenCalled(); expect(preview).not.toHaveBeenCalled();
});
test('alternate method or suffix cannot reach the bridge', async () => {
  expect((await request(app).delete(path)).status).toBe(404); expect((await request(app).post(path + '/history')).status).toBe(404);
  expect((await request(app).get(path + '/other')).status).toBe(404); expect(remove).not.toHaveBeenCalled(); expect(preview).not.toHaveBeenCalled();
});
