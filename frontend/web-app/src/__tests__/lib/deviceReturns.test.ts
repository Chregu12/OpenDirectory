import {
  CompanyOffboardingDevicesClient, DeviceReturnsClient, deviceReturnEtag, deviceReturnsReason, deviceReturnsError,
} from '@/lib/deviceReturns';
import { randomUUID } from 'crypto';

const mockGet = jest.fn(); const mockPost = jest.fn();
jest.mock('@/lib/api', () => ({ api: { get: (...args: unknown[]) => mockGet(...args), post: (...args: unknown[]) => mockPost(...args) } }));
const id = (number: number) => `10000000-0000-4000-8000-${String(number).padStart(12, '0')}`;
const actorUserId = id(1); const tenantId = id(2); const userId = id(3); const workflowId = id(4);
const deviceId = id(5); const assignmentId = id(6); const requestId = id(7); const operationId = id(8);
const reason = 'Gerät wird am Empfang zurückgegeben';
const date = '2026-10-19T10:00:00.000Z';
const permissions = ['devices.inventory.read', 'devices.inventory.create', 'devices.inventory.assign'];
const binding = { actorUserId, tenantId, userId, workflowId, eligibilityRevision: '9007199254740993' };
const target = { enabled: false, eligibilityRevision: binding.eligibilityRevision };
const envelope = { schemaVersion: 1, actorUserId, tenantId };
const base = `/api/devices/users/${userId}/offboarding-returns`;
const generalBase = '/api/devices/returns';
const cap = () => ({ ...envelope, deviceReturnsProtocol: 1, permissions, managementMode: 'inventory-only' });
const offCap = () => ({ ...envelope, deviceOffboardingReturnsProtocol: 1, userId, workflowId, target, permissions, managementMode: 'inventory-only' });
const device = (changes = {}) => ({ deviceId, assetId: 'ASSET-1', serialNumber: 'SN-1', deviceRevision: '9007199254740993', assignmentId, openRequestId: null, ...changes });
const preview = (changes = {}) => ({ ...offCap(), devices: [device()], total: 1, page: 1, limit: 25, ...changes });
const offHistory = (changes = {}) => ({ ...envelope, userId, workflowId, target, requests: [], total: 0, page: 1, limit: 25, ...changes });
const request = (changes = {}) => ({
  id: requestId, tenantId, workflowId, userId, deviceId, assignmentId, assetId: 'ASSET-1', serialNumber: 'SN-1', revision: '1',
  deviceRevision: '9007199254740993', currentDeviceRevision: '9007199254740993', status: 'requested', reason, actorUserId,
  requestedAt: date, eligibilityRevision: binding.eligibilityRevision, closedAt: null, closedByUserId: null,
  operationId, closingOperationId: null, inventoryOperationId: null, deliveryStatus: 'pending', ...changes,
});
const event = (changes = {}) => ({ id: operationId, tenantId, requestId, deviceId, assignmentId, type: 'device.return.requested', version: 1, actorUserId,
  correlationId: id(9), createdAt: date, before: null, after: { revision: '1', status: 'requested' }, inventoryOperationId: null, reason, deliveryStatus: 'pending', ...changes });
const history = (changes = {}) => ({ ...envelope, requestId, events: [event()], total: 1, page: 1, limit: 25, ...changes });
let data: Record<string, unknown>;
const clients: Array<DeviceReturnsClient | CompanyOffboardingDevicesClient> = [];
function company() { const current = new CompanyOffboardingDevicesClient(binding); clients.push(current); return current; }
function general() { const current = new DeviceReturnsClient(actorUserId); clients.push(current); return current; }
async function ready(current = company()) { await current.capabilities(); const snapshot = await current.preview(); await current.history(); return { current, snapshot }; }
async function detail(current = general()) { await current.capabilities(); const snapshot = await current.get(requestId); await current.history(requestId); return { current, snapshot }; }
function requestedResult(items: Array<{ deviceId?: string; assignmentId?: string; requestId?: string }>, changes = {}) {
  return { ...envelope, userId, workflowId, correlationId: id(9), results: items.map((item, index) => ({ deviceId: item.deviceId, assignmentId: item.assignmentId, requestId: item.requestId, status: 'requested', code: 200, operationId: id(100 + index), ...changes })) };
}
function decided(action = 'returned', changes = {}) {
  return request({ status: action, revision: '2', currentDeviceRevision: action === 'returned' ? '9007199254740994' : '9007199254740993',
    closedAt: date, closedByUserId: actorUserId, closingOperationId: id(11), inventoryOperationId: action === 'returned' ? id(12) : null, ...changes });
}
beforeEach(() => {
  jest.resetAllMocks();
  Object.defineProperty(crypto, 'randomUUID', { configurable: true, value: randomUUID });
  data = { [generalBase + '/capabilities']: cap(), [generalBase]: { ...envelope, requests: [request()], total: 1, page: 1, limit: 25 },
    [generalBase + '/' + requestId]: request(), [generalBase + '/' + requestId + '/history']: history(),
    [base + '/capabilities']: offCap(), [base]: preview(), [base + '/history']: offHistory() };
  mockGet.mockImplementation(async (url: string) => {
    if (!(url in data)) throw new Error('Unexpected ' + url);
    const value = data[url];
    return { status: 200, data: value, headers: url === generalBase + '/' + requestId ? { etag: deviceReturnEtag(value as ReturnType<typeof request>) } : {} };
  });
  mockPost.mockImplementation(async (url: string, body: { items?: Array<{ deviceId: string; assignmentId: string; requestId: string }>; action?: string }) => {
    if (url === base) return { status: 200, data: requestedResult(body.items) };
    const value = decided(body.action);
    return { status: 200, data: { ...envelope, deviceReturnsProtocol: 1, request: value, outcome: body.action, operationId: value.closingOperationId }, headers: { etag: deviceReturnEtag(value) } };
  });
});
afterEach(() => clients.splice(0).forEach(current => current.dispose()));

test('constructor does not fetch and general capability has no query or users.read dependency', async () => {
  const current = general(); company(); expect(mockGet).not.toHaveBeenCalled();
  await current.capabilities(); await current.list();
  expect(mockGet).toHaveBeenNthCalledWith(1, generalBase + '/capabilities', { signal: expect.any(AbortSignal) });
  expect(mockGet).toHaveBeenNthCalledWith(2, generalBase, { params: { page: 1, limit: 25 }, signal: expect.any(AbortSignal) });
});
test('offboarding reads exact paths, original parent and BIGINT values', async () => {
  const { snapshot } = await ready();
  expect(mockGet.mock.calls.map(([url]) => url)).toEqual([base + '/capabilities', base, base + '/history']);
  expect(mockGet).toHaveBeenNthCalledWith(1, base + '/capabilities', { params: { workflowId }, signal: expect.any(AbortSignal) });
  expect(mockGet).toHaveBeenNthCalledWith(2, base, { params: { workflowId, page: 1, limit: 25 }, signal: expect.any(AbortSignal) });
  expect(snapshot.devices[0].deviceRevision).toBe('9007199254740993'); expect(Object.isFrozen(snapshot.devices[0])).toBe(true);
});
test.each([
  ['protocol', { deviceReturnsProtocol: 2 }], ['missing protocol', { deviceReturnsProtocol: undefined }], ['schema', { schemaVersion: 2 }],
  ['actor', { actorUserId: id(99) }], ['capital actor', { actorUserId: 'AAAAAAAA-0000-4000-8000-000000000001' }],
  ['permission extra', { permissions: [...permissions, 'admin'] }], ['permission duplicate', { permissions: [permissions[0], permissions[0], permissions[2]] }],
  ['permission absent', { permissions: [] }], ['provider', { managementMode: 'mdm' }], ['extra', { token: 'secret' }],
])('general capabilities reject %s', async (_label, changes) => {
  data[generalBase + '/capabilities'] = { ...cap(), ...changes };
  await expect(general().capabilities()).rejects.toThrow(); expect(mockPost).not.toHaveBeenCalled();
});
test.each([
  ['tenant', { tenantId: id(99) }], ['workflow', { workflowId: id(99) }], ['user', { userId: id(99) }],
  ['positive target', { target: { enabled: true, eligibilityRevision: binding.eligibilityRevision } }],
  ['generation', { target: { enabled: false, eligibilityRevision: '9007199254740994' } }],
  ['target extra', { target: { ...target, authorizationRevision: '1' } }], ['protocol', { deviceOffboardingReturnsProtocol: 2 }],
])('offboarding capabilities reject %s before preview', async (_label, changes) => {
  data[base + '/capabilities'] = { ...offCap(), ...changes };
  await expect(company().capabilities()).rejects.toThrow(); expect(mockGet).toHaveBeenCalledTimes(1);
});
test('pins the general authoritative tenant across reloads and rejects self offboarding', async () => {
  const current = general(); await current.capabilities(); data[generalBase + '/capabilities'] = { ...cap(), tenantId: id(99) };
  await expect(current.capabilities()).rejects.toThrow();
  expect(() => new CompanyOffboardingDevicesClient({ ...binding, userId: actorUserId })).toThrow();
});
test.each([
  ['tenant', { tenantId: id(99) }], ['actor', { actorUserId: id(99) }], ['wrong page', { page: 2 }], ['short page', { total: 2 }],
  ['unsafe total', { total: Number.MAX_SAFE_INTEGER + 1 }], ['other limit', { limit: 24 }], ['extra', { newProtocol: 1 }],
  ['duplicate device', { devices: [device(), device()], total: 2 }],
  ['duplicate assignment', { devices: [device(), device({ deviceId: id(15) })], total: 2 }],
  ['missing assignment', { devices: [device({ assignmentId: undefined })] }],
  ['leading zero', { devices: [device({ deviceRevision: '01' })] }], ['numeric revision', { devices: [device({ deviceRevision: 1 })] }],
  ['overflow', { devices: [device({ deviceRevision: '9223372036854775808' })] }], ['untrimmed asset', { devices: [device({ assetId: ' ASSET-1' })] }],
  ['control serial', { devices: [device({ serialNumber: 'SN\n1' })] }], ['future rowfield', { devices: [device({ inventoryProtocol: 2 })] }],
])('preview rejects %s', async (_label, changes) => {
  const current = company(); await current.capabilities(); data[base] = preview(changes);
  await expect(current.preview()).rejects.toThrow(); expect(mockPost).not.toHaveBeenCalled();
});
test.each([0, -1, 1.5, NaN, Infinity, 1000001])('rejects invalid pagination %s without GET', async requestedPage => {
  const current = general(); await current.capabilities(); mockGet.mockClear(); await expect(current.list(requestedPage)).rejects.toThrow(); expect(mockGet).not.toHaveBeenCalled();
});
test('supports 25-row pages, exact filters and empty subsequent pages', async () => {
  const current = general(); await current.capabilities();
  data[generalBase] = { ...envelope, requests: Array.from({ length: 25 }, (_, index) => request({ id: id(100 + index) })), total: 26, page: 1, limit: 25 };
  expect((await current.list(1, 'requested')).requests).toHaveLength(25);
  expect(mockGet).toHaveBeenLastCalledWith(generalBase, { params: { page: 1, limit: 25, status: 'requested' }, signal: expect.any(AbortSignal) });
  data[generalBase] = { ...envelope, requests: [], total: 26, page: 3, limit: 25 }; expect((await current.list(3)).requests).toHaveLength(0);
});
test.each([
  ['unknown field', { externalSuccess: true }], ['numeric revision', { revision: 1 }], ['overflow current', { currentDeviceRevision: '9223372036854775808' }],
  ['backwards current', { currentDeviceRevision: '1' }], ['uppercase UUID', { deviceId: 'AAAAAAAA-0000-4000-8000-000000000005' }],
  ['pending closure', { closedAt: date, closedByUserId: actorUserId }], ['pending decision', { closingOperationId: id(11) }],
  ['pending inventory', { inventoryOperationId: id(12) }], ['untrimmed reason', { reason: ' ' + reason }], ['control reason', { reason: reason + '\n' }],
  ['deleted protocol', { inventoryProtocol: 2 }], ['bad timestamp', { requestedAt: 'invalid' }], ['self actor', { actorUserId: userId }],
  ['fake returned', { status: 'returned' }], ['fake changed', { status: 'assignment_changed' }], ['unknown state', { status: 'available' }],
])('strict request rejects %s', async (_label, changes) => {
  const current = general(); await current.capabilities(); data[generalBase] = { ...envelope, requests: [request(changes)], total: 1, page: 1, limit: 25 };
  await expect(current.list()).rejects.toThrow();
});
test.each(['W/"device-return-x"', '"device-return-x"', undefined, '"device-return-' + requestId + '-1-1"'])('requires strong exact combined ETag %s', async etag => {
  const current = general(); await current.capabilities(); mockGet.mockResolvedValueOnce({ status: 200, data: request(), headers: { etag } });
  await expect(current.get(requestId)).rejects.toThrow();
});
test('requires fresh preview and history, accepts explicit subset only, captures request UUID once', async () => {
  data[base] = preview({ devices: [device(), device({ deviceId: id(15), assignmentId: id(16), openRequestId: id(17) })], total: 2 });
  const { current, snapshot } = await ready();
  expect(() => current.capture(snapshot, [id(15)], { reason, confirm: true })).toThrow();
  expect(() => current.capture({ ...snapshot }, [deviceId], { reason, confirm: true })).toThrow();
  expect(() => current.capture(snapshot, [deviceId, deviceId], { reason, confirm: true })).toThrow();
  const intent = current.capture(snapshot, [deviceId], { reason: '  ' + reason + '  ', confirm: true });
  expect(intent.items).toHaveLength(1); expect(intent.items[0].requestId).toMatch(/^[a-f0-9-]{36}$/); expect(Object.isFrozen(intent.items[0])).toBe(true);
  await current.request(intent);
  expect(mockPost).toHaveBeenCalledWith(base, { workflowId, eligibilityRevision: binding.eligibilityRevision, reason, confirm: true, items: intent.items }, { signal: expect.any(AbortSignal) });
  await expect(current.request(intent)).rejects.toThrow(); expect(mockPost).toHaveBeenCalledTimes(1);
});
test('preview without following history and unknown subset cannot capture', async () => {
  const current = company(); await current.capabilities(); await current.history(); const snapshot = await current.preview();
  expect(() => current.capture(snapshot, [deviceId], { reason, confirm: true })).toThrow();
  await current.history(); expect(() => current.capture(snapshot, [id(88)], { reason, confirm: true })).toThrow();
});
test.each(['kurz', 'x'.repeat(501), '\n' + reason, reason + '\u0085'])('rejects bad reasons %s before posting', async invalid => {
  const { current, snapshot } = await ready(); expect(() => current.capture(snapshot, [deviceId], { reason: invalid, confirm: true })).toThrow(); expect(mockPost).not.toHaveBeenCalled();
});
test('Unicode reason counts code points and prohibits missing/extra confirmation fields', async () => {
  expect(deviceReturnsReason('😀'.repeat(500))).toHaveLength(1000);
  const { current, snapshot } = await ready();
  expect(() => current.capture(snapshot, [deviceId], { reason, confirm: false } as never)).toThrow();
  expect(() => current.capture(snapshot, [deviceId], { reason, confirm: true, token: 'forbidden' } as never)).toThrow();
});
test.each([
  ['actor', (value: ReturnType<typeof requestedResult>) => ({ ...value, actorUserId: id(99) })],
  ['tenant', (value: ReturnType<typeof requestedResult>) => ({ ...value, tenantId: id(99) })],
  ['order', (value: ReturnType<typeof requestedResult>) => ({ ...value, results: [...value.results].reverse() })],
  ['assignment', (value: ReturnType<typeof requestedResult>) => ({ ...value, results: value.results.map(result => ({ ...result, assignmentId: id(99) })) })],
  ['request UUID', (value: ReturnType<typeof requestedResult>) => ({ ...value, results: value.results.map(result => ({ ...result, requestId: id(99) })) })],
  ['missing receipt', (value: ReturnType<typeof requestedResult>) => ({ ...value, results: value.results.map(result => ({ ...result, operationId: null })) })],
  ['duplicate operation', (value: ReturnType<typeof requestedResult>) => ({ ...value, results: value.results.map(result => ({ ...result, operationId })) })],
  ['empty', (value: ReturnType<typeof requestedResult>) => ({ ...value, results: [] })],
])('ambiguous %s result invalidates reads without retry', async (_label, change) => {
  data[base] = preview({ devices: [device(), device({ deviceId: id(15), assignmentId: id(16) })], total: 2 });
  const { current, snapshot } = await ready(); const intent = current.capture(snapshot, snapshot.devices.map(value => value.deviceId), { reason, confirm: true });
  mockPost.mockResolvedValueOnce({ status: 200, data: change(requestedResult(intent.items)) });
  await expect(current.request(intent)).rejects.toThrow(); expect(current.canRecover(intent)).toBe(false); expect(mockPost).toHaveBeenCalledTimes(1);
});
test('validates partial results in original order and requires actual stop at first uncertain child', async () => {
  data[base] = preview({ devices: Array.from({ length: 3 }, (_, index) => device({ deviceId: id(20 + index), assignmentId: id(30 + index) })), total: 3 });
  const { current, snapshot } = await ready(); const intent = current.capture(snapshot, snapshot.devices.map(value => value.deviceId), { reason, confirm: true });
  const result = requestedResult(intent.items);
  const partial = { ...result, results: [result.results[0], { ...result.results[1], status: 'unconfirmed', code: 503, operationId: null }, { ...result.results[2], status: 'not_attempted', code: null, operationId: null }] };
  mockPost.mockResolvedValueOnce({ status: 207, data: partial }); expect((await current.request(intent)).results[2].status).toBe('not_attempted');
});
test.each([200, 207])('rejects HTTP status/partial-body disagreement %s', async responseStatus => {
  const { current, snapshot } = await ready(); const intent = current.capture(snapshot, [deviceId], { reason, confirm: true });
  mockPost.mockResolvedValueOnce({ status: responseStatus, data: requestedResult(intent.items, responseStatus === 200 ? { status: 'unconfirmed', code: 503, operationId: null } : {}) });
  await expect(current.request(intent)).rejects.toThrow();
});
test('unknown creation ACK recovers only original manifest after real readback, never new assignment', async () => {
  const { current, snapshot } = await ready(); const intent = current.capture(snapshot, [deviceId], { reason, confirm: true });
  mockPost.mockRejectedValueOnce(new Error('Lost ACK')); await expect(current.request(intent)).rejects.toThrow();
  await expect(current.request(intent, true)).rejects.toThrow();
  data[base] = preview({ devices: [device({ assignmentId: id(77), deviceRevision: '9007199254740995' })] });
  data[base + '/history'] = offHistory({ requests: [request({ id: intent.items[0].requestId, status: 'assignment_changed', currentDeviceRevision: '9007199254740995', closedAt: date, closedByUserId: actorUserId, inventoryOperationId: id(88) })], total: 1 });
  await ready(current); expect(current.canRecover(intent)).toBe(true);
  mockPost.mockResolvedValueOnce({ status: 200, data: requestedResult(intent.items, { status: 'already_requested' }) });
  await current.request(intent, true);
  expect(mockPost.mock.calls[0][1]).toEqual(mockPost.mock.calls[1][1]); expect(mockPost.mock.calls[1][1].items[0].assignmentId).toBe(assignmentId);
});
test.each(['returned', 'cancelled'] as const)('decision %s uses only explicit body and original combined ETag', async action => {
  const { current, snapshot } = await detail(); const intent = current.capture(snapshot, { action, reason, confirm: true });
  const value = await current.decide(intent); expect(value.outcome).toBe(action);
  expect(mockPost).toHaveBeenCalledWith(generalBase + '/' + requestId + '/decision', { action, reason, confirm: true }, { headers: { 'If-Match': '"device-return-' + requestId + '-1-9007199254740993"' }, signal: expect.any(AbortSignal) });
  await expect(current.decide(intent)).rejects.toThrow(); expect(mockPost).toHaveBeenCalledTimes(1);
});
test.each([
  ['request extra', { extra: true }], ['wrong user', { userId: id(99) }], ['wrong source revision', { deviceRevision: '2' }],
  ['wrong request revision', { revision: '3' }], ['wrong actor', { closedByUserId: id(99) }], ['wrong assignment', { assignmentId: id(99) }],
  ['reason overwritten', { reason: 'Eine andere ursprüngliche Begründung' }], ['missing actual release', { inventoryOperationId: null }],
])('decision rejects %s', async (_label, changes) => {
  const { current, snapshot } = await detail(); const intent = current.capture(snapshot, { action: 'returned', reason, confirm: true }); const value = decided('returned', changes);
  mockPost.mockResolvedValueOnce({ status: 200, data: { ...envelope, deviceReturnsProtocol: 1, request: value, outcome: 'returned', operationId: id(11) }, headers: { etag: deviceReturnEtag(value) } });
  await expect(current.decide(intent)).rejects.toThrow(); expect(mockPost).toHaveBeenCalledTimes(1);
});
test('historical decision recovery with newly assigned device sends no refreshed ETag or new assignment', async () => {
  const { current, snapshot } = await detail(); const intent = current.capture(snapshot, { action: 'returned', reason, confirm: true });
  mockPost.mockResolvedValueOnce({ status: 200, data: { request: null } }); await expect(current.decide(intent)).rejects.toThrow();
  await expect(current.decide(intent, true)).rejects.toThrow();
  const value = decided('returned', { currentDeviceRevision: '9007199254740999' });
  data[generalBase + '/' + requestId] = value;
  data[generalBase + '/' + requestId + '/history'] = history({ events: [event({ id: id(11), type: 'device.return.confirmed', before: { revision: '1', status: 'requested' }, after: { revision: '2', status: 'returned' }, inventoryOperationId: id(12) }), event()], total: 2 });
  await detail(current); expect(current.canRecover(intent)).toBe(true);
  mockPost.mockResolvedValueOnce({ status: 200, data: { ...envelope, deviceReturnsProtocol: 1, request: value, outcome: 'already_returned', operationId: id(11) }, headers: { etag: deviceReturnEtag(value) } });
  const recovered = await current.decide(intent, true); expect(recovered.request.currentDeviceRevision).toBe('9007199254740999');
  expect(mockPost.mock.calls[1][1]).toEqual(mockPost.mock.calls[0][1]); expect(mockPost.mock.calls[1][2].headers).toEqual(mockPost.mock.calls[0][2].headers);
});
test('derived assignment_changed has no fake return event and cannot authorize a decision', async () => {
  data[generalBase + '/' + requestId] = request({ status: 'assignment_changed', currentDeviceRevision: '9007199254740994', closedAt: date, closedByUserId: actorUserId, inventoryOperationId: id(12) });
  const { current, snapshot } = await detail(); expect(snapshot.status).toBe('assignment_changed');
  expect(() => current.capture(snapshot, { action: 'returned', reason, confirm: true })).toThrow(); expect(mockPost).not.toHaveBeenCalled();
});
test.each([
  ['tenant', { tenantId: id(99) }], ['assignment', { assignmentId: id(99) }], ['actor', { actorUserId: id(99) }], ['reason', { reason: 'Eine abweichende Begründung' }],
  ['invented state', { after: { revision: '1', status: 'assignment_changed' } }], ['fake release', { inventoryOperationId: id(12) }],
  ['before', { before: { revision: '1', status: 'requested' } }], ['unknown field', { unsupported: true }],
  ['missing version', { version: undefined }], ['wrong version', { version: 2 }],
])('history rejects %s event', async (_label, changes) => {
  const current = general(); await current.capabilities(); await current.get(requestId);
  data[generalBase + '/' + requestId + '/history'] = history({ events: [event(changes)] });
  await expect(current.history(requestId)).rejects.toThrow();
});
test('rejects foreign offboarding history and general filtered mismatches', async () => {
  const current = company(); await current.capabilities(); data[base + '/history'] = offHistory({ requests: [request({ userId: id(99) })], total: 1 });
  await expect(current.history()).rejects.toThrow();
  const other = general(); await other.capabilities(); await expect(other.list(1, 'returned')).rejects.toThrow();
});
test('stale capability response cannot resurrect disposed client', async () => {
  let resolve: (value: unknown) => void;
  mockGet.mockImplementationOnce(() => new Promise(value => { resolve = value; }));
  const current = general(); const pending = current.capabilities(); current.dispose(); resolve({ status: 200, data: cap() });
  await expect(pending).rejects.toThrow(); await expect(current.list()).rejects.toThrow(); expect(mockPost).not.toHaveBeenCalled();
});
test('session change invalidates remembered intents even after new readback', async () => {
  const { current, snapshot } = await ready(); const intent = current.capture(snapshot, [deviceId], { reason, confirm: true });
  mockPost.mockRejectedValueOnce(new Error('Lost ACK')); await expect(current.request(intent)).rejects.toThrow();
  window.dispatchEvent(new Event('od:session-error')); await ready(current);
  expect(current.canRecover(intent)).toBe(false); await expect(current.request(intent, true)).rejects.toThrow();
});
test('new clients cannot inherit another client recovery intent', async () => {
  const { current, snapshot } = await detail(); const intent = current.capture(snapshot, { action: 'cancelled', reason, confirm: true });
  mockPost.mockRejectedValueOnce(new Error('Lost ACK')); await expect(current.decide(intent)).rejects.toThrow();
  const next = await detail(); expect(next.current.canRecover(intent)).toBe(false); await expect(next.current.decide(intent, true)).rejects.toThrow();
});
test.each(['actor', 'tenant', 'protocol', 'MFA'] as const)('pre-write fresh capability rejects changed %s before POST without refreshing device versions', async field => {
  const { current, snapshot } = await detail(); const intent = current.capture(snapshot, { action: 'returned', reason, confirm: true });
  const before = mockGet.mock.calls.length;
  if (field === 'MFA') mockGet.mockRejectedValueOnce({ response: { status: 428 } });
  else data[generalBase + '/capabilities'] = { ...cap(), ...(field === 'actor' ? { actorUserId: id(99) } : field === 'tenant' ? { tenantId: id(99) } : { deviceReturnsProtocol: 2 }) };
  await expect(current.decide(intent)).rejects.toBeDefined(); expect(mockPost).not.toHaveBeenCalled();
  expect(mockGet.mock.calls.slice(before).map(([url]) => url)).toEqual([generalBase + '/capabilities']);
});
test('pre-write negative parent capability forbids a changed eligibility generation before request creation', async () => {
  const { current, snapshot } = await ready(); const intent = current.capture(snapshot, [deviceId], { reason, confirm: true });
  data[base + '/capabilities'] = { ...offCap(), target: { enabled: false, eligibilityRevision: '9007199254740994' } };
  await expect(current.request(intent)).rejects.toThrow(); expect(mockPost).not.toHaveBeenCalled();
});
test('an actual already_returned receipt from another operator remains historical even on the first acknowledged call', async () => {
  const { current, snapshot } = await detail(); const intent = current.capture(snapshot, { action: 'returned', reason, confirm: true });
  const value = decided('returned', { currentDeviceRevision: '9007199254740999', closedByUserId: id(99) });
  mockPost.mockResolvedValueOnce({ status: 200, data: { ...envelope, deviceReturnsProtocol: 1, request: value, outcome: 'already_returned', operationId: id(11) }, headers: { etag: deviceReturnEtag(value) } });
  expect((await current.decide(intent)).outcome).toBe('already_returned');
});
test('newly captured decisions cannot use fabricated copied snapshots or copied intent objects', async () => {
  const { current, snapshot } = await detail();
  expect(() => current.capture({ ...snapshot }, { action: 'returned', reason, confirm: true })).toThrow();
  const intent = current.capture(snapshot, { action: 'returned', reason, confirm: true });
  await expect(current.decide({ ...intent })).rejects.toThrow(); expect(mockPost).not.toHaveBeenCalled();
});
test('a superseded capability GET cannot restore authority after the next read generation', async () => {
  let resolve: (value: unknown) => void;
  mockGet.mockImplementationOnce(() => new Promise(value => { resolve = value; }));
  const current = general(); const pending = current.capabilities(); const rejected = expect(pending).rejects.toThrow();
  await current.capabilities(); resolve({ status: 200, data: cap() }); await rejected;
  expect((await current.list()).requests[0].id).toBe(requestId);
});
test('error mapping preserves explicit reload and no provider-success fallback', () => {
  [400, 401, 403, 404, 409, 412, 428, 503].forEach(code => expect(deviceReturnsError({ response: { status: code } })).toMatch(/neu laden/));
  expect(deviceReturnsError(null)).toMatch(/keine automatische Wiederholung/);
});
