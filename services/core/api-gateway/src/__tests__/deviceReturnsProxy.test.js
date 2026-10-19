'use strict';

const { randomUUID } = require('node:crypto');
const { deviceInventoryReceiver } = require('../middleware/deviceInventoryProxy');
const { INVENTORY_PERMISSIONS } = require('../../../../../packages/device-inventory-contract');
let request; let response; let next; let data; let fetchImpl;
beforeEach(() => {
  const userId = randomUUID(); request = { originalUrl: '/api/devices/returns', headers: { authorization: 'Bearer original' },
    user: { actor_type: 'user', identity_authorization: { userId, revision: '1', linkRevision: '1', rolesRevision: 'a'.repeat(64) } } };
  response = { status: jest.fn().mockReturnThis(), json: jest.fn().mockReturnThis() }; next = jest.fn();
  data = { schemaVersion: 1, deviceReturnsProtocol: 1, actorUserId: userId, tenantId: randomUUID(), permissions: INVENTORY_PERMISSIONS, managementMode: 'inventory-only' };
  fetchImpl = jest.fn(async () => Response.json(data));
});
test.each(['/api/devices/returns', '/api/devices/returns/capabilities', '/api/devices/returns/' + randomUUID() + '/decision',
  '/api/devices/users/' + randomUUID() + '/offboarding-returns?workflowId=' + randomUUID(), '/returns/' + randomUUID() + '/history', '/RETURNS'])('return route %s requires the separate actual receiver protocol', async path => {
  request.originalUrl = path; await deviceInventoryReceiver('https://device.test', { fetchImpl })(request, response, next);
  expect(next).toHaveBeenCalledTimes(1); expect(fetchImpl).toHaveBeenCalledWith(new URL('https://device.test/api/devices/returns/capabilities'), expect.objectContaining({ method: 'GET', headers: { Authorization: 'Bearer original', Accept: 'application/json' }, redirect: 'error', cache: 'no-store' }));
});
test.each([{ deviceReturnsProtocol: undefined, inventoryProtocol: 1 }, { actorUserId: randomUUID() }, { tenantId: 'foreign' },
  { permissions: ['devices.inventory.read'] }, { permissions: [...INVENTORY_PERMISSIONS, 'admin'] }, { managementMode: 'managed' }, { supportedActions: ['wipe'] }])('an old or ambiguous returns receiver cannot receive an actual operation %j', async change => {
  Object.assign(data, change); await deviceInventoryReceiver('https://device.test', { fetchImpl })(request, response, next);
  expect(next).not.toHaveBeenCalled(); expect(response.status).toHaveBeenCalledWith(503);
});
test('the gateway image includes the actual existing shared device contract', () => {
  const fs = require('node:fs'); const path = require('node:path');
  expect(fs.readFileSync(path.join(__dirname, '../../Dockerfile'), 'utf8')).toContain('COPY packages/device-inventory-contract/ /packages/device-inventory-contract/');
});
