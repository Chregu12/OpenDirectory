'use strict';

jest.mock('../db', () => ({ isAvailable: () => true, pool: { end: jest.fn() } }));
jest.mock('../middleware/oidcAuth', () => ({ oidcAuth: () => (req, _res, next) => {
  req.user = { sub: 'original-blueprint-owner', actor_type: req.headers['x-test-actor'] || 'user', roles: [], permissions: [] }; next();
} }));
jest.mock('../CompanyBlueprintAuthority', () => ({ CompanyBlueprintAuthority: jest.fn() }));
jest.mock('@opendirectory/grpc-event-bus', () => ({ EventBusClient: jest.fn(() => ({ connect: jest.fn(), publish: jest.fn(async () => {}) })) }), { virtual: true });
const { CompanyBlueprintAuthority } = require('../CompanyBlueprintAuthority');
const read = jest.fn(); CompanyBlueprintAuthority.mockImplementation(() => ({ read }));
const app = require('../index'); const request = require('supertest');
const route = '/api/identity/company-blueprints';
beforeEach(() => read.mockReset());
test('the separate GET forwards the original human and bearer without requiring a global role', async () => {
  read.mockResolvedValue({ actual: true }); const response = await request(app).get(route).set('Authorization', 'Bearer original');
  expect(response.status).toBe(200); expect(response.body).toEqual({ actual: true }); expect(response.headers['cache-control']).toBe('no-store');
  expect(read).toHaveBeenCalledWith({ sub: 'original-blueprint-owner', actor_type: 'user', roles: [], permissions: [] }, 'Bearer original');
});
test.each([{ tenantId: 'claimed' }, { userId: 'claimed' }, { target: 'claimed' }, { permission: 'policies.publish' }])('query selectors cannot reach the source: %j', async query => {
  const response = await request(app).get(route).query(query); expect(response.status).toBe(400); expect(response.headers['cache-control']).toBe('no-store'); expect(read).not.toHaveBeenCalled();
});
test.each([{}, [], { tenantId: 'claimed' }, { userId: 'claimed' }].map(body => ({ body })))('GET bodies cannot select or broaden authority: %j', async ({ body }) => {
  const response = await request(app).get(route).send(body); expect(response.status).toBe(400); expect(response.headers['cache-control']).toBe('no-store'); expect(read).not.toHaveBeenCalled();
});
test.each(['unused', ''])('API-key presence is forbidden, including an empty value: %s', async apiKey => {
  const response = await request(app).get(route).set('X-API-Key', apiKey); expect(response.status).toBe(400); expect(read).not.toHaveBeenCalled();
});
test.each(['application', 'workload'])('machine actor %s cannot reach the new GET source', async actor => {
  const response = await request(app).get(route).set('X-Test-Actor', actor); expect(response.status).toBe(403); expect(read).not.toHaveBeenCalled();
});
test.each(['post', 'put', 'delete', 'patch'])('the private source has no %s write or fallback route', async method => {
  const response = await request(app)[method](route).send({}); expect(response.status).toBe(404); expect(read).not.toHaveBeenCalled();
});
test('unrelated own-source suffixes are not admitted by the new access rule', async () => {
  const response = await request(app).get(route + '/target'); expect(response.status).toBe(404); expect(read).not.toHaveBeenCalled();
});
test.each([401, 403, 428, 503])('original authority error %i is never replaced by a fabricated source', async status => {
  read.mockRejectedValue(Object.assign(new Error('Actual blueprint source unavailable'), { status }));
  const response = await request(app).get(route).set('Authorization', 'Bearer original');
  expect(response.status).toBe(status); expect(response.headers['cache-control']).toBe('no-store'); expect(response.body.companyBlueprintProtocol).toBeUndefined(); expect(response.body.permissions).toBeUndefined();
});
