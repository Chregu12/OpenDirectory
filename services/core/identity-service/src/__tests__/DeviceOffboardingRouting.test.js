'use strict';

const { randomUUID } = require('node:crypto');
jest.mock('../db', () => ({ isAvailable: () => true, pool: { end: jest.fn() } }));
jest.mock('../middleware/oidcAuth', () => ({ oidcAuth: () => (req, _res, next) => { req.user = { sub: 'original-inventory-owner', actor_type: 'user' }; next(); } }));
jest.mock('../DeviceOffboardingAuthority', () => ({ DeviceOffboardingAuthority: jest.fn() }));
jest.mock('@opendirectory/grpc-event-bus', () => ({ EventBusClient: jest.fn(() => ({ connect: jest.fn(), publish: jest.fn(async () => {}) })) }), { virtual: true });
const { DeviceOffboardingAuthority } = require('../DeviceOffboardingAuthority');
const read = jest.fn(), readScoped = jest.fn(); DeviceOffboardingAuthority.mockImplementation(() => ({ read, readScoped }));
const app = require('../index'); const request = require('supertest');
const route = '/api/identity/device-offboarding'; const body = { workflowId: randomUUID(), userId: randomUUID() };
beforeEach(() => { read.mockReset(); readScoped.mockReset(); });
test('the separate device offboarding source preserves original bearer and exact body without requiring a global role', async () => {
  read.mockResolvedValue({ actual: true }); const response = await request(app).post(route).set('Authorization', 'Bearer original').send(body);
  expect(response.status).toBe(200); expect(response.headers['cache-control']).toBe('no-store');
  expect(read).toHaveBeenCalledWith({ sub: 'original-inventory-owner', actor_type: 'user' }, 'Bearer original', body);
});
test('query fields and API keys cannot reach the original source reader', async () => {
  expect((await request(app).post(route).query({ workflowId: body.workflowId }).send(body)).status).toBe(400);
  expect((await request(app).post(route).set('X-API-Key', 'unused').send(body)).status).toBe(400);
  expect((await request(app).post(route).set('X-API-Key', '').send(body)).status).toBe(400); expect(read).not.toHaveBeenCalled();
});
test('only the explicit private protocol selects the scoped parent source', async () => {
  readScoped.mockResolvedValue({ schemaVersion: 2 });
  const selected = { deviceId: randomUUID(), deviceRevision: '9007199254740993', revision: '1', ou: null };
  const response = await request(app).post(route).set('Authorization', 'Bearer original').set('X-OD-Device-Scope-Protocol', '1').send({ ...body, device: selected });
  expect(response.status).toBe(200); expect(response.headers['cache-control']).toBe('no-store');
  expect(readScoped).toHaveBeenCalledWith({ sub: 'original-inventory-owner', actor_type: 'user' }, 'Bearer original', { ...body, device: selected });
  expect(read).not.toHaveBeenCalled();
});
test.each(['2', 'true', '1, 1'])('unsupported private protocol %s never selects a source', async protocol => {
  const response = await request(app).post(route).set('X-OD-Device-Scope-Protocol', protocol).send(body);
  expect(response.status).toBe(400); expect(read).not.toHaveBeenCalled(); expect(readScoped).not.toHaveBeenCalled();
});
test.each([401, 403, 404, 409, 428, 503])('source error %i remains a failure, never a fabricated parent', async status => {
  read.mockRejectedValue(Object.assign(new Error('Actual source unavailable'), { status }));
  const response = await request(app).post(route).send(body); expect(response.status).toBe(status); expect(response.body.parent).toBeUndefined();
});
