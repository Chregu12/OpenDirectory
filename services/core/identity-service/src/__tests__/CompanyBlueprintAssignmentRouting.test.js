'use strict';

const { randomUUID } = require('node:crypto');
jest.mock('../db', () => ({ isAvailable: () => true, pool: { end: jest.fn() } }));
jest.mock('../middleware/oidcAuth', () => ({ oidcAuth: () => (req, _res, next) => {
  req.user = { sub: 'original-assignment-owner', actor_type: req.headers['x-test-actor'] || 'user', roles: [], permissions: [] }; next();
} }));
jest.mock('../CompanyBlueprintAssignmentAuthority', () => ({ CompanyBlueprintAssignmentAuthority: jest.fn() }));
jest.mock('@opendirectory/grpc-event-bus', () => ({ EventBusClient: jest.fn(() => ({ connect: jest.fn(), publish: jest.fn(async () => {}) })) }), { virtual: true });
const { CompanyBlueprintAssignmentAuthority } = require('../CompanyBlueprintAssignmentAuthority');
const read = jest.fn(); CompanyBlueprintAssignmentAuthority.mockImplementation(() => ({ read }));
const app = require('../index'); const request = require('supertest');
const route = '/api/identity/company-blueprint-assignments'; const userId = randomUUID();
beforeEach(() => read.mockReset());

test('the independent GET forwards the original roleless human and bearer without a target or global role', async () => {
  read.mockResolvedValue({ actual: true }); const result = await request(app).get(route).set('Authorization', 'Bearer original');
  expect(result.status).toBe(200); expect(result.body).toEqual({ actual: true }); expect(result.headers['cache-control']).toBe('no-store');
  expect(read).toHaveBeenCalledWith({ sub: 'original-assignment-owner', actor_type: 'user', roles: [], permissions: [] }, 'Bearer original');
});
test('the independent POST forwards exactly one target selector without app authority', async () => {
  read.mockResolvedValue({ actual: true }); const result = await request(app).post(route).set('Authorization', 'Bearer original').send({ userId });
  expect(result.status).toBe(200); expect(result.headers['cache-control']).toBe('no-store');
  expect(read).toHaveBeenCalledWith({ sub: 'original-assignment-owner', actor_type: 'user', roles: [], permissions: [] }, 'Bearer original', { userId });
});
test.each([{}, [], { userId }, { tenantId: 'claimed' }].map(body => ({ body })))('GET rejects all supplied bodies including empty JSON: %j', async ({ body }) => {
  const result = await request(app).get(route).send(body); expect(result.status).toBe(400); expect(result.headers['cache-control']).toBe('no-store'); expect(read).not.toHaveBeenCalled();
});
test.each([{}, [], { userId, tenantId: 'claimed' }, { target: { id: userId } }, { userId, permission: 'company.apps.assign' }].map(body => ({ body })))('POST cannot broaden the exact selector: %j', async ({ body }) => {
  const result = await request(app).post(route).send(body); expect(result.status).toBe(400); expect(read).not.toHaveBeenCalled();
});
test('POST without a selector is not silently converted into an actor-only GET', async () => {
  const result = await request(app).post(route); expect(result.status).toBe(400); expect(read).not.toHaveBeenCalled();
});
test.each(['get', 'post'])('%s rejects query selectors and API-key presence including empty values', async method => {
  for (const query of [{ tenantId: 'claimed' }, { userId }, { permission: 'policies.publish' }]) {
    const result = await request(app)[method](route).query(query).send(method === 'post' ? { userId } : undefined); expect(result.status).toBe(400);
  }
  for (const value of ['', 'unused']) {
    const result = await request(app)[method](route).set('X-API-Key', value).send(method === 'post' ? { userId } : undefined); expect(result.status).toBe(400);
  }
  expect(read).not.toHaveBeenCalled();
});
test.each(['get', 'post'])('%s never admits a workload or application actor', async method => {
  for (const actor of ['workload', 'application']) {
    const result = await request(app)[method](route).set('X-Test-Actor', actor).send(method === 'post' ? { userId } : undefined); expect(result.status).toBe(403);
  }
  expect(read).not.toHaveBeenCalled();
});
test.each(['head', 'put', 'patch', 'delete'])('the source has no implicit %s route', async method => {
  const result = await request(app)[method](route); expect(result.status).toBe(404); expect(read).not.toHaveBeenCalled();
});
test.each(['/target', '-other', '/history'])('near-boundary suffix %s cannot reach the private source', async suffix => {
  const result = await request(app).get(route + suffix); expect(result.status).toBe(404); expect(read).not.toHaveBeenCalled();
});
test.each([400, 401, 403, 404, 428, 503])('original authority denial %i is not replaced by a successful proof', async status => {
  read.mockRejectedValue(Object.assign(new Error('Original assignment source unavailable'), { status }));
  const result = await request(app).post(route).set('Authorization', 'Bearer original').send({ userId });
  expect(result.status).toBe(status); expect(result.headers['cache-control']).toBe('no-store'); expect(result.body.permissions).toBeUndefined(); expect(result.body.companyBlueprintAssignmentsProtocol).toBeUndefined();
});
