'use strict';
jest.mock('jose', () => ({ createRemoteJWKSet: jest.fn(), jwtVerify: jest.fn() }));
jest.mock('../../../../../packages/oidc-access-state', () => ({ createAccessStateClient: () => async () => {} }));
const request = require('supertest');
const { jwtVerify } = require('jose');
const { randomUUID } = require('node:crypto');
const { createInventoryApp } = require('../inventoryServer');
let agents, app; const id = randomUUID();
beforeEach(() => {
 jest.clearAllMocks();
 agents = Object.fromEntries(['get','manage','register','heartbeat','fleet','inventoryReport'].map(method => [method, jest.fn()]));
 const value = { deviceId: id, revision: '1' }; agents.get.mockResolvedValue(value); agents.manage.mockResolvedValue(value); agents.register.mockResolvedValue(value); agents.heartbeat.mockResolvedValue(value);
 jwtVerify.mockResolvedValue({ payload: { actor_type: 'user', token_use: 'access' } });
 app = createInventoryApp({ db: {}, inventory: {}, returns: {}, agents });
});
test('hardware report reads preserve the original human bearer and never accept a device credential as a human', async () => {
 agents.inventoryReport.mockResolvedValue({ status: 'missing' });
 const response = await request(app).get('/api/devices/' + id + '/agent/inventory').set('Authorization', 'Bearer original');
 expect(response.status).toBe(200); expect(response.headers['cache-control']).toBe('no-store'); expect(agents.inventoryReport).toHaveBeenCalledWith(id, {}, { actor_type: 'user', token_use: 'access' }, 'Bearer original');
 jwtVerify.mockRejectedValueOnce(new Error('Device token is not human')); expect((await request(app).get('/api/devices/' + id + '/agent/inventory').set('Authorization', 'Bearer odad_' + 'x'.repeat(43))).status).toBe(401);
});
test('fleet read and export use the original human bearer and preserve exact query selectors', async () => {
 agents.fleet.mockResolvedValueOnce({ fleet: { counts: { total: 0 } } });
 const response = await request(app).get('/api/devices/fleet?connectionStatus=offline').set('Authorization', 'Bearer original');
 expect(response.status).toBe(200); expect(response.headers['cache-control']).toBe('no-store'); expect(agents.fleet).toHaveBeenLastCalledWith({ connectionStatus: 'offline' }, { actor_type: 'user', token_use: 'access' }, 'Bearer original');
 agents.fleet.mockResolvedValueOnce({ tenantId: id, count: 0, csv: 'header\r\n' });
 const csv = await request(app).get('/api/devices/fleet/export?connectionStatus=offline').set('Authorization', 'Bearer original');
 expect(csv.status).toBe(200); expect(csv.headers['x-inventory-tenant']).toBe(id); expect(csv.headers['content-type']).toMatch(/^text\/csv/); expect(agents.fleet).toHaveBeenLastCalledWith({ connectionStatus: 'offline' }, expect.any(Object), 'Bearer original', true);
});
test('only exact machine registration reaches the device kernel without invoking human authentication', async () => {
 const input = { token: 'odae_' + 'a'.repeat(43), report: {} }; const response = await request(app).post('/api/device-agent/register').send(input);
 expect(response.status).toBe(201); expect(jwtVerify).not.toHaveBeenCalled(); expect(agents.register).toHaveBeenCalledWith(input, response.headers['x-correlation-id']); expect(response.headers['cache-control']).toBe('no-store');
});
test.each(['/api/device-agent/register?tenantId=foreign','/api/device-agent/heartbeat?force=true'])('machine selectors cannot override device scope (%s)', async path => { expect((await request(app).post(path).send({})).status).toBe(400); expect(agents.register).not.toHaveBeenCalled(); expect(agents.heartbeat).not.toHaveBeenCalled(); });
test('device credential is forwarded only to heartbeat, never to human inventory', async () => {
 const header = 'Bearer odad_' + 'b'.repeat(43); expect((await request(app).post('/api/device-agent/heartbeat').set('Authorization', header).send({ deviceId: id, report: {} })).status).toBe(200);
 expect(agents.heartbeat).toHaveBeenCalledWith({ deviceId: id, report: {} }, header, expect.any(String));
 jwtVerify.mockRejectedValueOnce(new Error('Not a human JWT')); expect((await request(app).get('/api/devices/' + id + '/agent').set('Authorization', header)).status).toBe(401); expect(agents.get).not.toHaveBeenCalled();
});
test.each(['X-API-Key','X-Enrollment-Token','Authorization'])('alternate credentials cannot enroll (%s)', async header => { expect((await request(app).post('/api/device-agent/register').set(header, 'alternate').send({})).status).toBe(401); expect(agents.register).not.toHaveBeenCalled(); });
test('agent credential rejection returns authentication failure, missing guards return unavailable', async () => {
 agents.heartbeat.mockRejectedValueOnce(Object.assign(new Error('Agent credential rejected'), { code: '28000' })); expect((await request(app).post('/api/device-agent/heartbeat').send({})).status).toBe(401);
 agents.heartbeat.mockRejectedValueOnce(Object.assign(new Error('Agent receiver unavailable'), { code: '42501' })); expect((await request(app).post('/api/device-agent/heartbeat').send({})).status).toBe(503);
});
test('human management preserves exact original bearer, ETag and explicit request body', async () => {
 const body = { reason: 'Explicit original decision', confirm: true }; const expected = `"agent-${id}-0"`;
 const response = await request(app).post('/api/devices/' + id + '/agent/issue').set('Authorization','Bearer original').set('If-Match',expected).send(body);
 expect(response.status).toBe(201); expect(agents.manage).toHaveBeenCalledWith(id,'issue',body,expected,{ actor_type:'user',token_use:'access' },'Bearer original',response.headers['x-correlation-id']);
});
