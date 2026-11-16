'use strict';
const { randomUUID } = require('node:crypto');
const express = require('express'); const request = require('supertest');
jest.mock('../CompanyMicrosoftBridge', () => ({ CompanyMicrosoftBridge: jest.fn() }));
jest.mock('../CompanyMicrosoftDelivery', () => ({ CompanyMicrosoftDelivery: jest.fn() }));
const preview = jest.fn(), sync = jest.fn(), recoveryPreview = jest.fn(), recover = jest.fn(); require('../CompanyMicrosoftDelivery').CompanyMicrosoftDelivery.mockImplementation(() => ({ preview, sync, recoveryPreview, recover }));
const methods = Object.fromEntries(['state', 'products', 'mappings', 'history', 'connect', 'bindPool', 'bindUser', 'retire'].map(name => [name, jest.fn()]));
require('../CompanyMicrosoftBridge').CompanyMicrosoftBridge.mockImplementation(() => methods);
const { companyMicrosoftRoutes } = require('../companyMicrosoftRoutes');
const id = randomUUID(), operation = randomUUID(), target = randomUUID();
const version = `"company-microsoft-connection-${id}-7"`;
const body = { reason: 'Explicit Microsoft binding review', confirm: true };
let app;
beforeEach(() => {
  jest.clearAllMocks(); preview.mockResolvedValue({ fingerprint: 'a'.repeat(64) }); sync.mockResolvedValue({ historical: false, result: {} }); recoveryPreview.mockResolvedValue({ attempt: null }); recover.mockResolvedValue({ historical: false, result: {} });
  for (const method of Object.values(methods)) method.mockResolvedValue({ connection: { id, revision: '7' }, pool: { id, revision: '1' }, user: { id, revision: '1' }, binding: { id, revision: '8' } });
  app = express(); app.use(express.json()); app.use((req, _res, next) => { req.user = { sub: 'original' }; next(); }); app.use('/microsoft', companyMicrosoftRoutes({}));
});
test('binding carries the original actor, explicit connection identity/version and operation key', async () => {
  const result = await request(app).post('/microsoft/pools/' + target + '/bind').set('Authorization', 'Bearer original').set('If-Match', version).set('Idempotency-Key', operation).send(body);
  expect(result.status).toBe(201); expect(result.headers['cache-control']).toBe('no-store');
  expect(methods.bindPool).toHaveBeenCalledWith(target, body, { id, revision: '7' }, operation, { sub: 'original' }, 'Bearer original');
});
test('renewal and retirement require the ETag for the exact path resource', async () => {
  const wrong = await request(app).post('/microsoft/connections/' + target + '/renew').set('If-Match', version).set('Idempotency-Key', operation).send(body);
  expect(wrong.status).toBe(412); expect(methods.connect).not.toHaveBeenCalled();
  const good = await request(app).post('/microsoft/connections/' + id + '/renew').set('If-Match', version).set('Idempotency-Key', operation).send(body);
  expect(good.status).toBe(200); expect(methods.connect).toHaveBeenCalledWith(body, operation, { sub: 'original' }, undefined, { id, revision: '7' });
});
test('missing, weak, wildcard or overflowing versions never reach a writer', async () => {
  for (const value of ['', '*', 'W/' + version, `"company-microsoft-connection-${id}-9223372036854775808"`]) {
    expect((await request(app).post('/microsoft/users/' + target + '/bind').set('If-Match', value).set('Idempotency-Key', operation).send(body)).status).toBe(428);
  }
  expect(methods.bindUser).not.toHaveBeenCalled();
});
test('API keys including blank values, GET bodies and caller selectors are rejected before reading or writing', async () => {
  for (const attempt of [request(app).get('/microsoft/state').set('X-API-Key', ''), request(app).get('/microsoft/state').send({}), request(app).get('/microsoft/state').query({ tenantId: id }), request(app).post('/microsoft/connections').query({ actorUserId: id })]) expect((await attempt).status).toBe(400);
  expect(methods.state).not.toHaveBeenCalled(); expect(methods.connect).not.toHaveBeenCalled();
});
test('unsupported verbs and paths cannot fall through to another provider', async () => {
  for (const attempt of [request(app).head('/microsoft/state'), request(app).delete('/microsoft/connections/' + id), request(app).post('/microsoft/assignLicense')]) expect((await attempt).status).toBe(404);
  for (const method of Object.values(methods)) expect(method).not.toHaveBeenCalled();
});
test('provider and SQL failures never expose secrets while source rejection keeps its status', async () => {
  methods.state.mockRejectedValueOnce(new Error('private secret')); const unavailable = await request(app).get('/microsoft/state'); expect(unavailable.status).toBe(503); expect(JSON.stringify(unavailable.body)).not.toContain('private secret');
  methods.state.mockRejectedValueOnce({ status: 428, message: 'Actual fresh MFA required' }); expect((await request(app).get('/microsoft/state')).status).toBe(428);
});
test('preview forwards only the original actor and canonical path targets; caller decisions are rejected', async () => {
  const result = await request(app).post('/microsoft/pools/' + id + '/users/' + target + '/preview').set('Authorization', 'Bearer original').send({}); expect(result.status).toBe(200);
  expect(preview).toHaveBeenCalledWith(id, target, { sub: 'original' }, 'Bearer original'); preview.mockClear();
  expect((await request(app).post('/microsoft/pools/' + id + '/users/' + target + '/preview').send({ desired: true })).status).toBe(400); expect(preview).not.toHaveBeenCalled();
});
test('sync forwards only the explicit original operation and body to the independently authorized service', async () => {
  const input = { ...body, fingerprint: 'a'.repeat(64), action: 'assign' };
  const result = await request(app).post('/microsoft/pools/' + id + '/users/' + target + '/sync').set('Authorization', 'Bearer original').set('Idempotency-Key', operation).send(input);
  expect(result.status).toBe(200); expect(sync).toHaveBeenCalledWith(id, target, input, operation, { sub: 'original' }, 'Bearer original');
});
test('recovery preview is bodyless and forwards only the canonical pair and original human', async () => {
  const path = '/microsoft/pools/' + id + '/users/' + target + '/recovery-preview';
  expect((await request(app).post(path).set('Authorization', 'Bearer original').send({})).status).toBe(200);
  expect(recoveryPreview).toHaveBeenCalledWith(id, target, { sub: 'original' }, 'Bearer original'); recoveryPreview.mockClear();
  expect((await request(app).post(path).send({ desired: true })).status).toBe(400); expect(recoveryPreview).not.toHaveBeenCalled();
});
test('recover requires its own operation key and cannot inherit a caller-selected authority', async () => {
  const path = '/microsoft/pools/' + id + '/users/' + target + '/recover';
  expect((await request(app).post(path).send(body)).status).toBe(400); expect(recover).not.toHaveBeenCalled();
  expect((await request(app).post(path).set('Authorization', 'Bearer original').set('Idempotency-Key', operation).send(body)).status).toBe(200);
  expect(recover).toHaveBeenCalledWith(id, target, body, operation, { sub: 'original' }, 'Bearer original');
});
