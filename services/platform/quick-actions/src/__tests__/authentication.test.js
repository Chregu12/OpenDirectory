'use strict';
jest.mock('../middleware/verifyApiToken', () => ({ verifyToken: jest.fn() }));
jest.mock('../../../../../packages/oidc-access-state', () => ({ createAccessStateClient: jest.fn(() => jest.fn(async () => {})) }));
const request = require('supertest');
const express = require('express');
const auth = require('../middleware/auth');
const { verifyToken } = require('../middleware/verifyApiToken');
const { validate, currentOperator } = require('../utils/delegation');
const { accessClaims } = require('./fixtures/claims');
const app = express(); app.use(auth); app.get('/private', (_req, response) => response.json({ operationId: currentOperator().operationId })); app.get('/health', (_req, response) => response.json({ healthy: true }));
beforeEach(() => { jest.clearAllMocks(); verifyToken.mockResolvedValue(accessClaims()); validate.mockResolvedValue(undefined); });
const invoke = () => request(app).get('/private').set('Authorization', 'Bearer header.payload.signature');
test.each([
  { sub: undefined }, { sub: '' }, { sub: ' ' }, { jti: undefined }, { jti: '' }, { exp: undefined }, { iat: undefined },
  { token_use: undefined }, { token_use: 'id' }, { token_use: 'device' }, { actor_type: 'workload' }, { actor_type: undefined },
  { sid: undefined }, { sid: 'not-a-session' }, { auth_time: 'now' }, { client_id: '' }, { identity_authorization: undefined },
])('malformed signed principal data cannot authorize or reach live source: %j', async patch => {
  verifyToken.mockResolvedValue(accessClaims(patch)); expect((await invoke()).status).toBe(401); expect(validate).not.toHaveBeenCalled();
});
test('a fresh live check runs on every request, has no positive authorization cache and binds an immutable operation', async () => {
  const first = await invoke(); const second = await invoke(); expect(first.status).toBe(200); expect(second.status).toBe(200); expect(validate).toHaveBeenCalledTimes(2);
  expect(first.body.operationId).not.toBe(second.body.operationId); expect(first.headers['cache-control']).toBe('no-store');
  validate.mockRejectedValue(Object.assign(new Error('unavailable'), { status: 503 })); expect((await invoke()).status).toBe(503);
});
test('health-prefix and HTTP-method guesses do not bypass the private boundary', async () => {
  expect((await request(app).get('/health')).status).toBe(200); expect((await request(app).get('/health/private')).status).toBe(401); expect((await request(app).post('/health')).status).toBe(401);
  expect(verifyToken).not.toHaveBeenCalled();
});
test('API keys and URL credentials cannot supplement or substitute for the verified access token', async () => {
  expect((await invoke().set('X-API-Key', 'ignored')).status).toBe(401);
  for (const field of ['token', 'access_token', 'api_key', 'service_token']) expect((await invoke().query({ [field]: 'ignored' })).status).toBe(401);
  expect(verifyToken).not.toHaveBeenCalled();
});
