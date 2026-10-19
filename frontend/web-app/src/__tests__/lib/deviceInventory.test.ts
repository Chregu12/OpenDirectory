import { api } from '@/lib/api';
import { Device, DeviceInventoryClient, deviceEtag, normalizeDeviceInput } from '@/lib/deviceInventory';

jest.mock('@/lib/api', () => ({ api: { get: jest.fn(), post: jest.fn(), put: jest.fn() } }));

const actorId = '11111111-1111-4111-8111-111111111111';
const tenantId = '22222222-2222-4222-8222-222222222222';
const deviceId = '33333333-3333-4333-8333-333333333333';
const recipientId = '44444444-4444-4444-8444-444444444444';
const assignmentId = '55555555-5555-4555-8555-555555555555';
const otherId = '66666666-6666-4666-8666-666666666666';
const values = { assetId: 'INV-001', serialNumber: 'SER-001', manufacturer: 'Framework', model: 'Laptop 13', deviceClass: 'laptop' as const, platform: 'linux' as const };
const profile = { ...values, osVersion: '', ownership: 'corporate' as const, purchaseDate: '', warrantyEnd: '', description: '' };
const device = (changes = {}): Device => ({ ...profile, id: deviceId, tenantId, revision: '1', lifecycle: 'available', managementMode: 'inventory-only', enrollmentStatus: 'not-enrolled', managementProvider: null,
  complianceStatus: 'unknown', lastSeen: null, assignedUserId: null, assignmentId: null, createdAt: '2026-10-19T10:00:00.000Z', updatedAt: '2026-10-19T10:00:00.000Z', ...changes });
const capabilities = (changes = {}) => ({ schemaVersion: 1, inventoryProtocol: 1, userId: actorId, tenantId, permissions: ['devices.inventory.read', 'devices.inventory.create', 'devices.inventory.assign'], managementMode: 'inventory-only', supportedActions: [], ...changes });
const event = (changes = {}) => ({ id: assignmentId, tenantId, deviceId, type: 'device.registered', version: 1, actorUserId: actorId, correlationId: otherId, createdAt: device().createdAt, before: null,
  after: { assignedUserId: null, assignmentId: null, revision: '1' }, deliveryStatus: 'pending', ...changes });
const page = (changes = {}) => ({ schemaVersion: 1, actorUserId: actorId, devices: [device()], total: 1, page: 1, limit: 25, ...changes });
const history = (changes = {}) => ({ schemaVersion: 1, actorUserId: actorId, deviceId, events: [event()], total: 1, page: 1, limit: 25, ...changes });
const directoryAccess = (changes = {}) => ({ subject: 'verified-human', userId: actorId, demoMode: false, directoryReadProtocol: 1, permissions: [], ...changes });
const clients: DeviceInventoryClient[] = [];

function deferred<Result>() {
  let resolve: (result: Result) => void;
  const promise = new Promise<Result>(complete => { resolve = complete; });
  return { promise, resolve: (result: Result) => resolve(result) };
}
async function ready(changes = {}) {
  (api.get as jest.Mock).mockImplementation(async (url: string) => {
    if (url === '/api/devices/capabilities') return { status: 200, data: capabilities(changes) };
    if (url === '/api/devices') return { status: 200, data: page() };
    if (url === '/api/identity/access') return { status: 200, data: directoryAccess() };
    if (url.endsWith('/history')) return { status: 200, data: history() };
    if (url === '/api/devices/' + deviceId) return { status: 200, data: device() };
    throw new Error('Unexpected HTTP read: ' + url);
  });
  const client = new DeviceInventoryClient(); clients.push(client); await client.reload(); return client;
}
beforeEach(() => jest.resetAllMocks());
afterEach(() => { clients.splice(0).forEach(client => client.dispose()); });

test('creation sends precisely normalized inventory values with defaults and binds the own tenant receipt', async () => {
  const client = await ready(); (api.post as jest.Mock).mockResolvedValue({ status: 201, data: device() });
  expect(await client.create({ ...values, assetId: '  INV-001  ' })).toEqual(device());
  expect(api.post).toHaveBeenCalledWith('/api/devices', profile, { signal: expect.any(AbortSignal) });
  expect((api.get as jest.Mock).mock.calls.filter(([url]) => url === '/api/devices/capabilities')).toHaveLength(2);
});

test.each([
  { assetId: ' ' }, { serialNumber: '' }, { manufacturer: 'secret\nvalue' }, { model: 'x'.repeat(121) },
  { purchaseDate: '2026-02-30' }, { purchaseDate: '0000-01-01' }, { purchaseDate: '2026-10-19', warrantyEnd: '2026-10-18' },
  { deviceClass: 'server' }, { platform: 'chromeos' }, { ownership: 'leased' }, { description: '\u007f' },
  { tenantId }, { assignedUserId: recipientId }, { enrollmentStatus: 'enrolled' }, { password: 'secret' },
])('unsafe, extra or invalid creation input is rejected before any HTTP call: %j', async changes => {
  const client = new DeviceInventoryClient(); clients.push(client);
  await expect(client.create({ ...values, ...changes } as any)).rejects.toThrow(); expect(api.get).not.toHaveBeenCalled(); expect(api.post).not.toHaveBeenCalled();
});

test('Unicode length, real leap days and ownership defaults follow the inventory contract', () => {
  expect(normalizeDeviceInput({ ...values, model: '😀'.repeat(120), purchaseDate: '2024-02-29' })).toMatchObject({ ownership: 'corporate', osVersion: '', purchaseDate: '2024-02-29' });
  expect(() => normalizeDeviceInput({ ...values, purchaseDate: '2025-02-29' })).toThrow();
});

test.each([
  { schemaVersion: 0 }, { inventoryProtocol: undefined }, { inventoryProtocol: 2 }, { userId: 'admin' }, { userId: actorId.toUpperCase().replace('1111', 'ABCD') },
  { tenantId: null }, { permissions: ['admin'] }, { supportedActions: ['wipe'] }, { managementMode: 'managed' }, { mock: true },
])('down-level, unbound and remote-management capabilities fail closed: %j', async changes => {
  const client = new DeviceInventoryClient(); clients.push(client);
  (api.get as jest.Mock).mockResolvedValue({ status: 200, data: capabilities(changes) });
  await expect(client.reload()).rejects.toThrow(); await expect(client.list()).rejects.toThrow(); await expect(client.create(values)).rejects.toThrow();
  expect(api.get).toHaveBeenCalledTimes(1); expect(api.post).not.toHaveBeenCalled();
});

test('absent read authority cannot list devices or histories or discover users', async () => {
  const client = await ready({ permissions: [] });
  await expect(client.list()).rejects.toThrow(); await expect(client.get(deviceId)).rejects.toThrow(); await expect(client.history(deviceId)).rejects.toThrow(); await expect(client.users()).rejects.toThrow();
  expect(api.get).toHaveBeenCalledTimes(1);
});

test('search and pagination use server totals, page and limit instead of filtering a downloaded list', async () => {
  const client = await ready(); (api.get as jest.Mock).mockResolvedValue({ status: 200, data: page({ total: 26, page: 2 }) });
  expect(await client.list(2, '  Laptop  ')).toMatchObject({ total: 26, page: 2, limit: 25 });
  expect(api.get).toHaveBeenLastCalledWith('/api/devices', { params: { page: 2, limit: 25, search: 'Laptop' }, signal: expect.any(AbortSignal) });
});

test.each([
  { schemaVersion: 0 }, { actorUserId: recipientId }, { page: 2 }, { limit: 50 }, { total: 2 }, { total: -1 },
  { devices: [device(), device()], total: 2 }, { devices: [device({ tenantId: otherId })] }, { devices: [device({ assetId: ' unnormalized ' })] },
  { devices: [device({ revision: '9223372036854775808' })] }, { devices: [device({ revision: '1\n' })] },
  { devices: [device({ assignedUserId: recipientId })] }, { devices: [device({ lifecycle: 'assigned' })] },
  { devices: [device({ managementProvider: 'intune' })] }, { devices: [device({ lastSeen: device().createdAt })] },
  { devices: [device({ complianceStatus: 'compliant' })] }, { devices: [device({ createdAt: 'yesterday' })] }, { demo: true },
])('wrong actors, tenants, partial pages and fabricated device states never become inventory: %j', async changes => {
  const client = await ready(); (api.get as jest.Mock).mockResolvedValue({ status: 200, data: page(changes) });
  await expect(client.list()).rejects.toThrow(); await expect(client.list()).rejects.toThrow(); expect(api.get).toHaveBeenCalledTimes(2);
});

test.each([{ id: recipientId }, { tenantId: otherId }, { model: ' padded ' }, { unknownField: 'private' }])('detail receipts are bound to the exact requested canonical record: %j', async changes => {
  const client = await ready(); (api.get as jest.Mock).mockResolvedValue({ status: 200, data: device(changes) }); await expect(client.get(deviceId)).rejects.toThrow();
});

test('assignment uses the exact strong BIGINT ETag, no actor selectors, and exactly the next revision', async () => {
  const client = await ready(); const snapshot = device({ revision: '9007199254740993' });
  const receipt = device({ revision: '9007199254740994', assignedUserId: recipientId, assignmentId, lifecycle: 'assigned' });
  (api.put as jest.Mock).mockResolvedValue({ status: 200, data: receipt });
  expect(await client.assign(snapshot, { userId: recipientId })).toEqual(receipt);
  expect(deviceEtag(snapshot)).toBe('"device-' + deviceId + '-9007199254740993"');
  expect(api.put).toHaveBeenCalledWith('/api/devices/' + deviceId + '/assignment', { userId: recipientId }, { headers: { 'If-Match': deviceEtag(snapshot) }, signal: expect.any(AbortSignal) });
});

test.each([
  { revision: '1' }, { revision: '3' }, { revision: '2', assetId: 'changed' }, { revision: '2', serialNumber: 'changed' },
  { revision: '2', manufacturer: 'changed' }, { revision: '2', model: 'changed' }, { revision: '2', deviceClass: 'desktop' },
  { revision: '2', platform: 'windows' }, { revision: '2', osVersion: 'changed' }, { revision: '2', ownership: 'byod' },
  { revision: '2', purchaseDate: '2026-10-19' }, { revision: '2', warrantyEnd: '2027-10-19' }, { revision: '2', description: 'changed' },
  { revision: '2', id: otherId }, { revision: '2', tenantId: otherId }, { revision: '2', assignedUserId: otherId },
  { revision: '2', assignmentId: null }, { revision: '2', createdAt: '2026-10-18T10:00:00.000Z' }, { revision: '2', enrollmentStatus: 'enrolled' },
])('stale revisions and changes outside the assignment cannot confirm a write: %j', async changes => {
  const client = await ready();
  (api.put as jest.Mock).mockResolvedValue({ status: 200, data: device({ revision: '2', assignedUserId: recipientId, assignmentId, lifecycle: 'assigned', ...changes }) });
  await expect(client.assign(device(), { userId: recipientId })).rejects.toThrow();
  await expect(client.assign(device(), { userId: recipientId })).rejects.toThrow(); expect(api.put).toHaveBeenCalledTimes(1);
});

test('reassignment must replace the active assignment ID and release must clear both identifiers', async () => {
  const client = await ready(); const assigned = device({ lifecycle: 'assigned', assignedUserId: recipientId, assignmentId });
  (api.put as jest.Mock).mockResolvedValue({ status: 200, data: device({ revision: '2', assignedUserId: otherId, assignmentId, lifecycle: 'assigned' }) });
  await expect(client.assign(assigned, { userId: otherId })).rejects.toThrow();
  await client.reload(); (api.put as jest.Mock).mockResolvedValue({ status: 200, data: device({ revision: '2' }) });
  expect(await client.assign(assigned, { userId: null })).toMatchObject({ revision: '2', assignedUserId: null, assignmentId: null, lifecycle: 'available' });
});

test.each([{ userId: 'not-a-uuid' }, { userId: recipientId, tenantId }, {}, { userId: undefined }])('assignment accepts exactly canonical userId or null: %j', async input => {
  const client = await ready(); await expect(client.assign(device(), input as any)).rejects.toThrow(); expect(api.put).not.toHaveBeenCalled(); expect(api.get).toHaveBeenCalledTimes(1);
});

test.each([{ permissions: ['devices.inventory.read'] }, { userId: otherId }, { tenantId: otherId }, { inventoryProtocol: 0 }])('fresh capabilities bind user, tenant, protocol and permission immediately before writes: %j', async changes => {
  const client = await ready(); (api.get as jest.Mock).mockResolvedValue({ status: 200, data: capabilities(changes) });
  await expect(client.create(values)).rejects.toThrow(); expect(api.post).not.toHaveBeenCalled();
  (api.get as jest.Mock).mockResolvedValueOnce({ status: 200, data: capabilities() }); await client.reload();
  await expect(client.assign(device(), { userId: recipientId })).rejects.toThrow(); expect(api.put).not.toHaveBeenCalled();
});

test.each([202, 204, 207])('HTTP %s with a device-shaped body does not confirm creation or assignment', async status => {
  const client = await ready(); (api.post as jest.Mock).mockResolvedValue({ status, data: device() }); await expect(client.create(values)).rejects.toThrow();
  await client.reload(); (api.put as jest.Mock).mockResolvedValue({ status, data: device({ lifecycle: 'assigned', assignedUserId: recipientId, assignmentId, revision: '2' }) });
  await expect(client.assign(device(), { userId: recipientId })).rejects.toThrow();
});

test.each([{ tenantId: otherId }, { revision: '2' }, { assetId: 'different' }, { lifecycle: 'assigned', assignedUserId: recipientId, assignmentId }])('creation receipts must match the submitted profile and safe initial state: %j', async changes => {
  const client = await ready(); (api.post as jest.Mock).mockResolvedValue({ status: 201, data: device(changes) }); await expect(client.create(values)).rejects.toThrow();
});

test.each([409, 412, 503])('uncertain HTTP %s writes are sent once and require an explicit reload', async status => {
  const client = await ready(); (api.post as jest.Mock).mockRejectedValue({ response: { status } });
  await expect(client.create(values)).rejects.toEqual({ response: { status } }); await expect(client.create(values)).rejects.toThrow(); expect(api.post).toHaveBeenCalledTimes(1);
  (api.post as jest.Mock).mockResolvedValue({ status: 201, data: device() }); await client.reload(); expect(await client.create(values)).toEqual(device()); expect(api.post).toHaveBeenCalledTimes(2);
});

test('missing users.read uses the canonical-ID fallback without fetching any profile', async () => {
  const client = await ready(); expect(await client.users()).toBeNull(); expect(api.get).toHaveBeenLastCalledWith('/api/identity/access');
  expect((api.get as jest.Mock).mock.calls.some(([url]) => url === '/api/users')).toBe(false);
});

test('the real directory user list is gated by separate current users.read capability', async () => {
  const client = await ready(); const user = { id: recipientId, username: 'recipient', email: 'recipient@example.test', enabled: true, revision: '1', createdAt: device().createdAt };
  (api.get as jest.Mock).mockImplementation(async (url: string) => {
    if (url === '/api/identity/access') return { status: 200, data: directoryAccess({ permissions: ['users.read'] }) };
    if (url === '/api/users') return { status: 200, data: { users: [user], total: 26, page: 2, limit: 25 } };
    throw new Error('Unexpected request');
  });
  expect(await client.users(2, 'recipient')).toMatchObject({ users: [user], total: 26, page: 2 });
  expect(api.get).toHaveBeenLastCalledWith('/api/users', { params: { page: 2, limit: 25, search: 'recipient' }, signal: expect.any(AbortSignal) });
});

test.each([{ userId: otherId }, { demoMode: true }, { directoryReadProtocol: 0, permissions: ['users.read'] }])('unbound, demo and down-level user directories never disclose profiles: %j', async changes => {
  const client = await ready(); (api.get as jest.Mock).mockResolvedValue({ data: directoryAccess(changes) }); await expect(client.users()).rejects.toThrow();
  expect((api.get as jest.Mock).mock.calls.some(([url]) => url === '/api/users')).toBe(false);
});

test('history binds actual actor envelopes and device IDs while retaining actual historical actors', async () => {
  const client = await ready(); const actual = event({ actorUserId: recipientId });
  (api.get as jest.Mock).mockResolvedValue({ status: 200, data: history({ events: [actual] }) });
  expect(await client.history(deviceId)).toMatchObject({ events: [actual], total: 1 });
  expect(api.get).toHaveBeenLastCalledWith('/api/devices/' + deviceId + '/history', { params: { page: 1, limit: 25 }, signal: expect.any(AbortSignal) });
});

test.each([
  { actorUserId: otherId }, { deviceId: otherId }, { total: 2 }, { events: [event({ tenantId: otherId })] },
  { events: [event({ deviceId: otherId })] }, { events: [event({ deliveryStatus: 'delivered' })] },
  { events: [event({ version: 2 })] }, { events: [event({ correlationId: 'guessed' })] },
  { events: [event({ after: { assignedUserId: recipientId, assignmentId, revision: '1' } })] },
  { events: [event({ type: 'device.assigned' })] },
  { events: [event({ type: 'device.assignment.released', before: { assignedUserId: null, assignmentId: null, revision: '1' }, after: { assignedUserId: null, assignmentId: null, revision: '2' } })] },
])('malformed or foreign audit history is never displayed as success: %j', async changes => {
  const client = await ready(); (api.get as jest.Mock).mockResolvedValue({ status: 200, data: history(changes) }); await expect(client.history(deviceId)).rejects.toThrow();
});

test('an expired session aborts deferred capabilities before a create can dispatch', async () => {
  const client = await ready(); const pending = deferred<any>(); (api.get as jest.Mock).mockReturnValue(pending.promise);
  const result = client.create(values); const rejected = expect(result).rejects.toThrow();
  const signal = (api.get as jest.Mock).mock.calls.at(-1)[1].signal;
  window.dispatchEvent(new CustomEvent('od:session-error')); expect(signal.aborted).toBe(true);
  pending.resolve({ status: 200, data: capabilities() }); await rejected; expect(api.post).not.toHaveBeenCalled();
});

test('a late mutation receipt after a session error stays unconfirmed and cannot retry', async () => {
  const client = await ready(); const pending = deferred<any>(); (api.post as jest.Mock).mockReturnValue(pending.promise);
  const result = client.create(values); const rejected = expect(result).rejects.toThrow();
  await Promise.resolve(); await Promise.resolve(); await Promise.resolve(); expect(api.post).toHaveBeenCalledTimes(1);
  const signal = (api.post as jest.Mock).mock.calls[0][2].signal;
  window.dispatchEvent(new CustomEvent('od:session-error')); expect(signal.aborted).toBe(true);
  pending.resolve({ status: 201, data: device() }); await rejected;
  await expect(client.create(values)).rejects.toThrow(); expect(api.post).toHaveBeenCalledTimes(1);
});

test('a 401 on one request invalidates and aborts concurrent late inventory reads', async () => {
  const client = await ready(); const pending = deferred<any>();
  (api.get as jest.Mock).mockImplementation((url: string) => url === '/api/devices' ? pending.promise : Promise.reject({ response: { status: 401 } }));
  const listing = client.list(); const rejected = expect(listing).rejects.toThrow();
  const signal = (api.get as jest.Mock).mock.calls.at(-1)[1].signal;
  await expect(client.get(deviceId)).rejects.toEqual({ response: { status: 401 } }); expect(signal.aborted).toBe(true);
  pending.resolve({ status: 200, data: page() }); await rejected;
});

test('caller cancellation prevents late reads without invalidating an otherwise current session', async () => {
  const client = await ready(); const pending = deferred<any>(); (api.get as jest.Mock).mockReturnValueOnce(pending.promise);
  const controller = new AbortController(); const listing = client.list(1, '', controller.signal); const rejected = expect(listing).rejects.toThrow();
  controller.abort(); pending.resolve({ status: 200, data: page() }); await rejected;
  expect(await client.get(deviceId)).toEqual(device());
});
