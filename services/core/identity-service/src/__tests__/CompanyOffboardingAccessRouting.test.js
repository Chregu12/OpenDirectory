'use strict';

const { randomUUID } = require('node:crypto');
jest.mock('../db', () => ({ isAvailable: () => true, pool: { end: jest.fn() } }));
jest.mock('../middleware/oidcAuth', () => ({ oidcAuth: () => (req, _res, next) => { req.user = { sub: 'independent-operator', actor_type: 'user' }; next(); } }));
jest.mock('../CompanyOffboardingAccess', () => ({ CompanyOffboardingAccess: jest.fn() }));
jest.mock('@opendirectory/grpc-event-bus', () => ({ EventBusClient: jest.fn(() => ({ connect: jest.fn(), publish: jest.fn(async () => {}) })) }), { virtual: true });
const { CompanyOffboardingAccess } = require('../CompanyOffboardingAccess');
const capabilities = jest.fn(); const preview = jest.fn(); const history = jest.fn(); const revoke = jest.fn();
CompanyOffboardingAccess.mockImplementation(() => ({ capabilities, preview, history, revoke }));
const app = require('../index');
const request = require('supertest');
const target = randomUUID(); const workflowId = randomUUID(); const path = `/api/users/${target}/company-offboarding-access`;
beforeEach(() => { capabilities.mockReset(); preview.mockReset(); history.mockReset(); revoke.mockReset(); });
test.each([['/capabilities', capabilities], ['', preview], ['/history', history]])('GET %s forwards original independent operator, selectors and bearer', async (suffix, method) => {
  method.mockResolvedValue({ actual: true }); const selectors = suffix === '/capabilities' ? { workflowId } : { workflowId, kind: 'role', page: '2', limit: '25' };
  const response = await request(app).get(path + suffix).query(selectors).set('Authorization', 'Bearer original');
  expect(response.status).toBe(200); expect(response.headers['cache-control']).toBe('no-store');
  expect(method).toHaveBeenCalledWith(target, selectors, { sub: 'independent-operator', actor_type: 'user' }, 'Bearer original');
});
test.each([['revoked', 200], ['already_revoked', 200], ['unconfirmed', 207], ['not_attempted', 207]])('POST %s returns HTTP %s without claiming completion', async (status, code) => {
  const result = { results: [{ status }] }; revoke.mockResolvedValue(result);
  const response = await request(app).post(path).set('Authorization', 'Bearer original').send({ workflowId });
  expect(response.status).toBe(code); expect(response.body).toEqual(result); expect(response.headers['cache-control']).toBe('no-store');
  expect(revoke).toHaveBeenCalledWith(target, { workflowId }, { sub: 'independent-operator', actor_type: 'user' }, 'Bearer original');
});
test('query, GET body and API keys fail before the bridge', async () => {
  expect((await request(app).post(path).query({ kind: 'role' }).send({})).status).toBe(400);
  for (const suffix of ['', '/capabilities', '/history']) {
    expect((await request(app).get(path + suffix).send({ userId: target })).status).toBe(400);
    expect((await request(app).get(path + suffix).send([])).status).toBe(400);
    expect((await request(app).get(path + suffix).set('X-API-Key', 'unused')).status).toBe(400);
  }
  expect((await request(app).post(path).set('X-API-Key', 'unused').send({})).status).toBe(400);
  for (const method of [capabilities, preview, history, revoke]) expect(method).not.toHaveBeenCalled();
});
test('alternate methods and suffixes cannot reach the bridge', async () => {
  for (const operation of [request(app).delete(path), request(app).post(path + '/capabilities'), request(app).post(path + '/history'), request(app).get(path + '/other')]) expect((await operation).status).toBe(404);
  for (const method of [capabilities, preview, history, revoke]) expect(method).not.toHaveBeenCalled();
});
test.each([401, 403, 409, 412, 428, 503])('HTTP %s source and preflight errors remain errors, never mixed successes', async status => {
  revoke.mockRejectedValue(Object.assign(new Error('Actual source failure'), { status }));
  const response = await request(app).post(path).send({ workflowId }); expect(response.status).toBe(status); expect(response.body.results).toBeUndefined();
});
