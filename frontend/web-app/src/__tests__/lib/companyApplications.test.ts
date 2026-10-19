import { api } from '@/lib/api';
import { CompanyApplicationsClient, CompanyPool, companyApplicationsError, companyPoolEtag, normalizeCompanyPoolInput } from '@/lib/companyApplications';

jest.mock('@/lib/api', () => ({ api: { get: jest.fn(), post: jest.fn(), patch: jest.fn() } }));

const actorId = '11111111-1111-4111-8111-111111111111';
const tenantId = '22222222-2222-4222-8222-222222222222';
const poolId = '33333333-3333-4333-8333-333333333333';
const userId = '44444444-4444-4444-8444-444444444444';
const assignmentId = '55555555-5555-4555-8555-555555555555';
const otherId = '66666666-6666-4666-8666-666666666666';
const base = '/api/licenses/company';
const values = { name: 'Example App', vendor: 'Example Vendor', description: 'Local business app', totalSeats: 2, reason: 'Reviewed company license stock' };
const editInput = { ...values, name: 'Updated App', totalSeats: 3, confirm: true as const };
const editCapabilities = (changes = {}) => ({ schemaVersion: 1, companyPoolEditProtocol: 1, actorUserId: actorId, tenantId, poolId, poolRevision: record.revision, ...changes });
const editResponse = (changes = {}) => {
  const data = cleanPool({ name: editInput.name, totalSeats: 3, availableSeats: 3, revision: '2', ...changes });
  return { status: 200, data, headers: { etag: companyPoolEtag(data) } };
};
const cleanPool = (changes = {}): CompanyPool => ({ id: poolId, tenantId, revision: '1', name: values.name, vendor: values.vendor, description: values.description, totalSeats: values.totalSeats,
  usedSeats: 0, availableSeats: 2, licenseType: 'per_user', allocationMode: 'local-only', createdAt: '2026-10-19T10:00:00.000Z', updatedAt: '2026-10-19T10:00:00.000Z', ...changes });
const capabilities = (changes = {}) => ({ schemaVersion: 1, companyLicenseProtocol: 1, actorUserId: actorId, tenantId,
  permissions: ['company.apps.read', 'company.apps.create', 'company.apps.assign'], allocationMode: 'local-only', supportedTargets: ['user'], ...changes });
const assignment = (changes = {}) => ({ id: assignmentId, userId, assignedAt: '2026-10-19T10:00:00.000Z', assignedBy: actorId, grantId: otherId, ...changes });
const event = (changes = {}) => ({ id: assignmentId, type: 'app.license.pool.created', version: 1, actorUserId: actorId, userId: null,
  correlationId: otherId, createdAt: '2026-10-19T10:00:00.000Z', beforeRevision: null, afterRevision: '1', deliveryStatus: 'pending', ...changes });
const envelope = (changes = {}) => ({ schemaVersion: 1, actorUserId: actorId, tenantId, total: 1, page: 1, limit: 25, ...changes });
const directoryAccess = (changes = {}) => ({ subject: 'signed-human', userId: actorId, demoMode: false, permissions: [], directoryReadProtocol: 1, ...changes });
const returnAssignment = (changes = {}) => ({ id: assignmentId, poolId, poolRevision: '9007199254740993', name: values.name, vendor: values.vendor,
  grantId: otherId, assignedAt: '2026-10-19T10:00:00.000Z', ...changes });
const returnResult = (changes = {}) => ({ poolId, assignmentId, status: 'released', code: 200, ...changes });
const returnReceipt = (results = [returnResult()], changes = {}) => ({ schemaVersion: 1, actorUserId: actorId, tenantId, userId, correlationId: otherId, results, ...changes });
const returnInput = { reason: 'Reviewed inactive employee licenses', confirm: true as const };
let access: ReturnType<typeof capabilities>;
let record: CompanyPool;
let poolEnvelope: any;
let assignmentEnvelope: any;
let historyEnvelope: any;
let directory: any;
let returnEnvelope: any;
const clients: CompanyApplicationsClient[] = [];

async function getResponse(url: string) {
  if (url === base + '/capabilities') return { status: 200, data: access };
  if (url === base + '/pools') return { status: 200, data: poolEnvelope };
  if (url === base + '/pools/' + poolId) return { status: 200, data: record, headers: { etag: companyPoolEtag(record) } };
  if (url === base + '/pools/' + poolId + '/edit-capabilities') return { status: 200, data: editCapabilities(), headers: { 'cache-control': 'no-store' } };
  if (url.endsWith('/license-returns')) return { status: 200, data: returnEnvelope };
  if (url.endsWith('/assignments')) return { status: 200, data: assignmentEnvelope };
  if (url.endsWith('/history')) return { status: 200, data: historyEnvelope };
  if (url === '/api/identity/access') return { status: 200, data: directory };
  if (url === '/api/users') return { status: 200, data: { users: [{ id: userId, username: 'member', email: 'member@example.test', enabled: true, revision: '1', createdAt: record.createdAt }], total: 1, page: 1, limit: 25 } };
  throw new Error('Unexpected contract endpoint: ' + url);
}
function newClient() { const client = new CompanyApplicationsClient(); clients.push(client); return client; }
async function ready(changes = {}) { access = capabilities(changes); const client = newClient(); await client.reload(); return client; }
function deferred<Result>() {
  let resolve: (result: Result) => void;
  const promise = new Promise<Result>(complete => { resolve = complete; });
  return { promise, resolve: (result: Result) => resolve(result) };
}
beforeEach(() => {
  jest.resetAllMocks(); access = capabilities(); record = cleanPool(); poolEnvelope = envelope({ pools: [record] });
  assignmentEnvelope = envelope({ poolId, assignments: [assignment()] }); historyEnvelope = envelope({ poolId, events: [event()] }); directory = directoryAccess();
  returnEnvelope = envelope({ userId, target: { enabled: false, deleted: false, eligibilityRevision: '9007199254740993' }, assignments: [returnAssignment()] });
  (api.get as jest.Mock).mockImplementation(getResponse);
});
afterEach(() => clients.splice(0).forEach(client => client.dispose()));

test('creates only normalized exact company fields and confirms the empty local pool', async () => {
  const client = await ready(); (api.post as jest.Mock).mockResolvedValue({ status: 201, data: record });
  expect(await client.create({ ...values, name: '  Example App  ', reason: ' Reviewed company license stock ' })).toEqual(record);
  expect(api.post).toHaveBeenCalledTimes(1);
  expect(api.post).toHaveBeenCalledWith(base + '/pools', values, { signal: expect.any(AbortSignal) });
});
test.each([{ name: '' }, { vendor: ' ' }, { name: 'a\nname' }, { vendor: 'a\u007fvendor' }, { name: 'x'.repeat(161) },
  { description: 'x'.repeat(2001) }, { totalSeats: 0 }, { totalSeats: 10001 }, { totalSeats: 1.5 }, { totalSeats: '2' }, { totalSeats: NaN },
  { reason: 'short' }, { reason: 'x'.repeat(501) }, { reason: 'bad\nreason for change' }, { tenantId }, { userId }, { allocationMode: 'cloud' }, { confirm: true }])
('rejects unsafe or extra creation fields without HTTP: %j', async changes => {
  const client = newClient(); await expect(client.create({ ...values, ...changes } as any)).rejects.toThrow();
  expect(api.get).not.toHaveBeenCalled(); expect(api.post).not.toHaveBeenCalled();
});
test('text limits count Unicode characters and preserve precise seat integers', () => {
  expect(normalizeCompanyPoolInput({ ...values, name: '😀'.repeat(160), totalSeats: 10000 })).toMatchObject({ totalSeats: 10000 });
});
test.each([{ schemaVersion: 2 }, { companyLicenseProtocol: undefined }, { companyLicenseProtocol: 0 }, { actorUserId: 'admin' },
  { tenantId: otherId.toUpperCase().replace('6666', 'AAAA') }, { permissions: ['licenses.assign'] }, { permissions: ['company.apps.read', 'company.apps.read'] },
  { allocationMode: 'microsoft-graph' }, { supportedTargets: ['group'] }, { supportedTargets: ['user', 'device'] }, { supportedTargets: [] }, { demo: true }])
('does not admit broad, down-level or demo capabilities: %j', async changes => {
  access = capabilities(changes); const client = newClient();
  await expect(client.reload()).rejects.toThrow(); await expect(client.list()).rejects.toThrow(); expect(api.get).toHaveBeenCalledTimes(1);
});
test('read authority is explicit and cannot be invented through returned permission array mutation', async () => {
  const client = await ready({ permissions: [] }); const result = await client.reload(); result.permissions.push('company.apps.read');
  await expect(client.list()).rejects.toThrow(); await expect(client.get(poolId)).rejects.toThrow(); await expect(client.history(poolId)).rejects.toThrow();
  await expect(client.listAssignments(poolId)).rejects.toThrow(); await expect(client.users()).rejects.toThrow(); expect(api.post).not.toHaveBeenCalled();
});
test('search is a literal server-side query with exact page and limit, never a tenant selector', async () => {
  const client = await ready(); poolEnvelope = envelope({ pools: [record], page: 2, total: 26 });
  expect(await client.list(2, '  app%_literal  ')).toMatchObject({ page: 2, total: 26 });
  expect(api.get).toHaveBeenCalledWith(base + '/pools', { params: { page: 2, limit: 25, search: 'app%_literal' }, signal: expect.any(AbortSignal) });
});
test.each([{ actorUserId: userId }, { tenantId: otherId }, { schemaVersion: 2 }, { page: 2 }, { limit: 50 }, { total: 2 }, { total: -1 },
  { pools: [cleanPool(), cleanPool()], total: 2 }, { pools: [cleanPool({ tenantId: otherId })] }, { mock: true }])
('rejects wrong actor/home, truncated pages and unknown envelope keys: %j', async changes => {
  const client = await ready(); poolEnvelope = { ...poolEnvelope, ...changes }; await expect(client.list()).rejects.toThrow();
  const count = (api.get as jest.Mock).mock.calls.length; await expect(client.list()).rejects.toThrow(); expect(api.get).toHaveBeenCalledTimes(count);
});
test.each([{ name: ' padded ' }, { vendor: 'Vendor\n' }, { description: 'bad\u0000text' }, { usedSeats: 1 }, { availableSeats: -1 },
  { totalSeats: 10001, availableSeats: 10001 }, { revision: '01' }, { revision: '1\n' }, { revision: '9223372036854775808' },
  { licenseType: 'per_device' }, { allocationMode: 'installed' }, { installed: true }, { createdAt: 'today' }, { updatedAt: '2025-10-19T10:00:00.000Z' }])
('pool receipts require canonical text, BIGINT, conservation and no fabricated state: %j', async changes => {
  const client = await ready(); poolEnvelope.pools = [cleanPool(changes)]; await expect(client.list()).rejects.toThrow();
});
test.each([undefined, 'W/"company-pool-' + poolId + '-1"', '"company-pool-' + poolId + '-2"', '"other"'])
('detail requires the exact strong ETag: %j', async etag => {
  const client = await ready(); (api.get as jest.Mock).mockImplementation(url => url === base + '/pools/' + poolId ? { status: 200, data: record, headers: { etag } } : getResponse(url));
  await expect(client.get(poolId)).rejects.toThrow();
});
test('detail checks requested UUID, own home and actor freshness before release', async () => {
  const client = await ready(); access.actorUserId = otherId; await expect(client.get(poolId)).rejects.toThrow();
});
test.each([{ actorUserId: otherId }, { tenantId: otherId }, { poolId: otherId }, { total: 2 }, { assignments: [assignment(), assignment()], total: 2 },
  { assignments: [assignment({ userId: 'member' })] }, { assignments: [assignment({ grantId: null })] }, { assignments: [assignment({ status: 'installed' })] }])
('assignment pages cannot cross actor, pool, shape or cardinality: %j', async changes => {
  const client = await ready(); assignmentEnvelope = { ...assignmentEnvelope, ...changes }; await expect(client.listAssignments(poolId)).rejects.toThrow();
});
test.each([{ tenantId: otherId }, { actorUserId: otherId }, { poolId: otherId }, { events: [event({ deliveryStatus: 'delivered' })] },
  { events: [event({ afterRevision: '2' })] }, { events: [event({ userId })] }, { events: [event({ version: 2 })] },
  { events: [event({ type: 'app.license.assigned', userId, beforeRevision: '1', afterRevision: '3' })] },
  { events: [event(), event({ id: otherId })], total: 2 }])
('history is real pending delivery evidence, not fabricated success or inconsistent revision: %j', async changes => {
  const client = await ready(); historyEnvelope = { ...historyEnvelope, ...changes }; await expect(client.history(poolId)).rejects.toThrow();
});
test('assign/revoke bind exact accepted snapshots, original target, BIGINT If-Match and unchanged pool fields', async () => {
  const client = await ready(); record = cleanPool({ revision: '9007199254740993' });
  const snapshot = await client.get(poolId);
  const assigned = cleanPool({ revision: '9007199254740994', usedSeats: 1, availableSeats: 1 });
  (api.post as jest.Mock).mockResolvedValueOnce({ status: 201, data: assigned });
  const result = await client.assign(snapshot, { userId, reason: values.reason, confirm: true });
  expect(api.post).toHaveBeenLastCalledWith(base + '/pools/' + poolId + '/assignments', { userId, reason: values.reason, confirm: true }, { headers: { 'If-Match': '"company-pool-' + poolId + '-9007199254740993"' }, signal: expect.any(AbortSignal) });
  const target = (await client.listAssignments(poolId)).assignments[0];
  (api.post as jest.Mock).mockResolvedValueOnce({ status: 200, data: cleanPool({ revision: '9007199254740995' }) });
  await client.revoke(result, target, { userId, reason: values.reason, confirm: true });
  expect(api.post).toHaveBeenLastCalledWith(base + '/pools/' + poolId + '/assignments/' + assignmentId + '/revoke', { userId, reason: values.reason, confirm: true }, { headers: { 'If-Match': '"company-pool-' + poolId + '-9007199254740994"' }, signal: expect.any(AbortSignal) });
});
test.each([{ confirm: false }, { confirm: undefined }, { userId: 'someone' }, { userId: userId.toUpperCase().replace('4444', 'ABCD') }, { reason: 'short' }, { tenantId }])
('assignment confirmation is exact and extra selectors never go to the server: %j', async changes => {
  const client = await ready(); const snapshot = await client.get(poolId); (api.get as jest.Mock).mockClear();
  await expect(client.assign(snapshot, { userId, reason: values.reason, confirm: true, ...changes } as any)).rejects.toThrow(); expect(api.get).not.toHaveBeenCalled(); expect(api.post).not.toHaveBeenCalled();
});
test('unattested clones and prior-generation snapshots cannot be used to write', async () => {
  const client = await ready(); const snapshot = await client.get(poolId); await client.reload();
  await expect(client.assign(snapshot, { userId, reason: values.reason, confirm: true })).rejects.toThrow(); expect(api.post).not.toHaveBeenCalled();
  await client.reload(); const current = await client.get(poolId);
  await expect(client.assign({ ...current }, { userId, reason: values.reason, confirm: true })).rejects.toThrow(); expect(api.post).not.toHaveBeenCalled();
});
test('revocation requires an actual assignment receipt for this pool, even when profile discovery is unavailable', async () => {
  const client = await ready(); record = cleanPool({ usedSeats: 1, availableSeats: 1 }); const snapshot = await client.get(poolId);
  await expect(client.users()).resolves.toBeNull();
  await expect(client.revoke(snapshot, assignment(), { userId, reason: values.reason, confirm: true })).rejects.toThrow(); expect(api.post).not.toHaveBeenCalled();
});
test.each([{ revision: '3' }, { usedSeats: 0, availableSeats: 2 }, { totalSeats: 3, usedSeats: 1, availableSeats: 2 },
  { tenantId: otherId }, { id: otherId }, { name: 'Different' }, { createdAt: '2026-10-18T10:00:00.000Z' }])
('successful HTTP is not sufficient proof of assignment: %j', async changes => {
  const client = await ready(); const snapshot = await client.get(poolId);
  (api.post as jest.Mock).mockResolvedValue({ status: 201, data: cleanPool({ revision: '2', usedSeats: 1, availableSeats: 1, ...changes }) });
  await expect(client.assign(snapshot, { userId, reason: values.reason, confirm: true })).rejects.toThrow(); expect(api.post).toHaveBeenCalledTimes(1);
  await expect(client.list()).rejects.toThrow();
});
test.each([401, 403, 409, 412, 428, 503])('native failure %s is retained, explicitly reloadable and never retried', async status => {
  const client = await ready(); const snapshot = await client.get(poolId); const error = { response: { status } };
  (api.post as jest.Mock).mockRejectedValue(error);
  await expect(client.assign(snapshot, { userId, reason: values.reason, confirm: true })).rejects.toBe(error);
  expect(companyApplicationsError(error)).toMatch(/neu laden/); await expect(client.list()).rejects.toThrow(); expect(api.post).toHaveBeenCalledTimes(1);
});
test('actor/tenant or permission changes at writer preflight prevent the POST', async () => {
  const client = await ready(); const snapshot = await client.get(poolId); access.permissions = ['company.apps.read'];
  await expect(client.assign(snapshot, { userId, reason: values.reason, confirm: true })).rejects.toThrow(); expect(api.post).not.toHaveBeenCalled();
});
test('late session failure discards an otherwise successful write and aborts in-flight requests', async () => {
  const client = await ready(); const snapshot = await client.get(poolId); const delayed = deferred<any>();
  (api.post as jest.Mock).mockReturnValue(delayed.promise);
  const operation = client.assign(snapshot, { userId, reason: values.reason, confirm: true });
  await Promise.resolve(); await Promise.resolve(); await Promise.resolve();
  expect(api.post).toHaveBeenCalledTimes(1);
  window.dispatchEvent(new Event('od:session-error'));
  expect((api.post as jest.Mock).mock.calls[0][2].signal.aborted).toBe(true);
  delayed.resolve({ status: 201, data: cleanPool({ revision: '2', usedSeats: 1, availableSeats: 1 }) });
  await expect(operation).rejects.toThrow(); await expect(client.list()).rejects.toThrow(); expect(api.post).toHaveBeenCalledTimes(1);
});
test('reload suppresses late old reads even if transport ignores abort', async () => {
  const client = await ready(); const delayed = deferred<any>();
  (api.get as jest.Mock).mockImplementation(url => url === base + '/pools' ? delayed.promise : getResponse(url));
  const operation = client.list(); await client.reload(); delayed.resolve({ status: 200, data: poolEnvelope });
  await expect(operation).rejects.toThrow(); expect(await client.get(poolId)).toEqual(record);
});
test('concurrent writer attempts never duplicate HTTP writes', async () => {
  const client = await ready(); const snapshot = await client.get(poolId); const delayed = deferred<any>();
  (api.post as jest.Mock).mockReturnValue(delayed.promise);
  const operation = client.assign(snapshot, { userId, reason: values.reason, confirm: true });
  await expect(client.assign(snapshot, { userId, reason: values.reason, confirm: true })).rejects.toThrow();
  delayed.resolve({ status: 201, data: cleanPool({ revision: '2', usedSeats: 1, availableSeats: 1 }) }); await operation; expect(api.post).toHaveBeenCalledTimes(1);
});
test('profile discovery is separately authorized and absence returns UUID fallback without listing users', async () => {
  const client = await ready(); await expect(client.users()).resolves.toBeNull();
  expect((api.get as jest.Mock).mock.calls.some(([url]) => url === '/api/users')).toBe(false);
});
test('the real directory picker requests only active own users after actor/protocol authorization', async () => {
  const client = await ready(); directory = directoryAccess({ permissions: ['users.read'] });
  expect((await client.users()).users[0].id).toBe(userId);
  expect(api.get).toHaveBeenCalledWith('/api/users', { params: { page: 1, limit: 25, enabled: 'true' }, signal: expect.any(AbortSignal) });
});
test.each([{ userId: otherId }, { demoMode: true }, { directoryReadProtocol: undefined, permissions: ['users.read'] }])
('directory picker cannot use another actor, demo or down-level access: %j', async changes => {
  const client = await ready(); directory = directoryAccess(changes); await expect(client.users()).rejects.toThrow();
  expect((api.get as jest.Mock).mock.calls.some(([url]) => url === '/api/users')).toBe(false);
});
test.each([0, -1, 1.5, 1000001])('invalid page %s performs no company list read', async page => {
  const client = await ready(); await expect(client.list(page)).rejects.toThrow(); expect(api.get).toHaveBeenCalledTimes(1);
});

test('employee return preview is read-only, immutable and bounded, without directory profile discovery', async () => {
  const client = await ready(); const preview = await client.previewLicenseReturns(userId);
  expect(preview.assignments).toEqual([returnAssignment()]); expect(Object.isFrozen(preview)).toBe(true);
  expect(Object.isFrozen(preview.target)).toBe(true); expect(Object.isFrozen(preview.assignments)).toBe(true); expect(Object.isFrozen(preview.assignments[0])).toBe(true);
  expect(api.get).toHaveBeenCalledWith(base + '/users/' + userId + '/license-returns', { params: { page: 1, limit: 25 }, signal: expect.any(AbortSignal) });
  expect((api.get as jest.Mock).mock.calls.map(([url]) => url)).toEqual([base + '/capabilities', base + '/capabilities', base + '/users/' + userId + '/license-returns', base + '/capabilities']);
  expect(api.post).not.toHaveBeenCalled();
});
test.each([{ schemaVersion: 2 }, { actorUserId: otherId }, { tenantId: otherId }, { userId: otherId }, { page: 2 }, { limit: 50 }, { total: 2 }, { total: -1 }, { total: 1.5 }, { extra: true },
  { target: { enabled: 'false', deleted: false, eligibilityRevision: '1' } }, { target: { enabled: false, deleted: false, eligibilityRevision: '0' } },
  { target: { enabled: true, deleted: true, eligibilityRevision: '1' } },
  { target: { enabled: false, deleted: false, eligibilityRevision: '01' } }, { target: { enabled: false, deleted: false, eligibilityRevision: '9223372036854775808' } },
  { target: { enabled: false, deleted: false, eligibilityRevision: '1', tenantId } }, { target: { enabled: false, eligibilityRevision: '1' } },
  ...[{ poolRevision: '01' }, { poolRevision: '1\n' }, { poolRevision: '9223372036854775808' }, { poolId: 'foreign' }, { id: 'assignment' }, { grantId: null },
    { name: '' }, { name: ' padded ' }, { name: 'x'.repeat(161) }, { vendor: 'bad\nvendor' }, { assignedAt: 'today' }, { extra: true }].map(changes => ({ assignments: [returnAssignment(changes)] })),
  { assignments: [returnAssignment(), returnAssignment()], total: 2 },
  { assignments: [returnAssignment(), returnAssignment({ id: otherId, grantId: userId })], total: 2 },
  { assignments: [returnAssignment(), returnAssignment({ id: otherId, poolId: otherId })], total: 2 },
])('rejects malformed employee return preview before exposing data: %j', async changes => {
  const client = await ready(); returnEnvelope = { ...returnEnvelope, ...changes };
  await expect(client.previewLicenseReturns(userId)).rejects.toThrow(); await expect(client.list()).rejects.toThrow(); expect(api.post).not.toHaveBeenCalled();
});
test.each([{ user: 'employee', page: 1 }, { user: userId, page: 0 }, { user: userId, page: 1.5 }, { user: userId, page: 1000001 }])
('rejects invalid employee or page without target reads: %j', async ({ user, page }) => {
  const client = await ready(); await expect(client.previewLicenseReturns(user, page)).rejects.toThrow(); expect(api.get).toHaveBeenCalledTimes(1);
});
test('employee return uses only the exact preview page and per-item BIGINT revisions, with fresh authority and no If-Match', async () => {
  const client = await ready(); returnEnvelope = { ...returnEnvelope, page: 2, total: 26 }; const preview = await client.previewLicenseReturns(userId, 2);
  (api.post as jest.Mock).mockResolvedValue({ status: 200, data: returnReceipt() }); (api.get as jest.Mock).mockClear();
  expect(await client.returnLicenses(preview, { ...returnInput, reason: '  ' + returnInput.reason + '  ' })).toEqual(returnReceipt());
  expect(api.post).toHaveBeenCalledTimes(1);
  expect(api.post).toHaveBeenCalledWith(base + '/users/' + userId + '/license-returns', {
    ...returnInput, assignments: [{ poolId, assignmentId, poolRevision: '9007199254740993' }],
  }, { signal: expect.any(AbortSignal) });
  expect((api.get as jest.Mock).mock.calls.map(([url]) => url)).toEqual([base + '/capabilities', base + '/capabilities']);
  await expect(client.returnLicenses(preview, returnInput)).rejects.toThrow(); expect(api.post).toHaveBeenCalledTimes(1);
});
test.each([{ target: { enabled: true, deleted: false, eligibilityRevision: '1' } }, { assignments: [], total: 0 }])
('active employees and empty pages remain readable but cannot be returned: %j', async changes => {
  const client = await ready(); returnEnvelope = { ...returnEnvelope, ...changes }; const preview = await client.previewLicenseReturns(userId);
  await expect(client.returnLicenses(preview, returnInput)).rejects.toThrow(); expect(api.post).not.toHaveBeenCalled();
});
test('deleted employee with a disabled source flag can return existing licenses', async () => {
  const client = await ready(); returnEnvelope.target = { enabled: false, deleted: true, eligibilityRevision: '2' }; const preview = await client.previewLicenseReturns(userId);
  (api.post as jest.Mock).mockResolvedValue({ status: 200, data: returnReceipt() }); await client.returnLicenses(preview, returnInput); expect(api.post).toHaveBeenCalledTimes(1);
});
test.each(['clone', 'foreign client', 'reload', 'new preview', 'newer pool', 'other write'])('rejects %s return snapshots without a return POST', async scenario => {
  const client = await ready(); const preview = await client.previewLicenseReturns(userId); let snapshot = preview;
  if (scenario === 'clone') snapshot = { ...preview };
  if (scenario === 'foreign client') { const other = await ready(); await expect(other.returnLicenses(snapshot, returnInput)).rejects.toThrow(); return; }
  if (scenario === 'reload') await client.reload();
  if (scenario === 'new preview') await client.previewLicenseReturns(userId);
  if (scenario === 'newer pool') { record = cleanPool({ revision: '9007199254740994' }); await client.get(poolId); }
  if (scenario === 'other write') { (api.post as jest.Mock).mockResolvedValue({ status: 201, data: record }); await client.create(values); (api.post as jest.Mock).mockClear(); }
  await expect(client.returnLicenses(snapshot, returnInput)).rejects.toThrow(); expect(api.post).not.toHaveBeenCalled();
});
test.each([{ reason: 'short' }, { reason: 'x'.repeat(501) }, { reason: 'bad\nreturn reason' }, { confirm: false }, { confirm: undefined }, { tenantId }, { assignments: [] }])
('return confirmation rejects extra or invalid input without HTTP: %j', async changes => {
  const client = await ready(); const preview = await client.previewLicenseReturns(userId); (api.get as jest.Mock).mockClear();
  await expect(client.returnLicenses(preview, { ...returnInput, ...changes } as any)).rejects.toThrow(); expect(api.get).not.toHaveBeenCalled(); expect(api.post).not.toHaveBeenCalled();
});
function threeReturns() {
  returnEnvelope.assignments = [returnAssignment(), returnAssignment({ id: userId, poolId: userId, grantId: actorId }), returnAssignment({ id: otherId, poolId: otherId, grantId: tenantId })];
  returnEnvelope.total = 3;
  return [returnResult(), returnResult({ poolId: userId, assignmentId: userId, status: 'unconfirmed', code: 503 }), returnResult({ poolId: otherId, assignmentId: otherId, status: 'not_attempted', code: null })];
}
test('207 preserves ordered released, unconfirmed and not-attempted results without claiming rollback or retrying', async () => {
  const client = await ready(); const results = threeReturns(); const preview = await client.previewLicenseReturns(userId);
  (api.post as jest.Mock).mockResolvedValue({ status: 207, data: returnReceipt(results) });
  expect(await client.returnLicenses(preview, returnInput)).toEqual(returnReceipt(results)); expect(api.post).toHaveBeenCalledTimes(1);
});
test.each([{ actorUserId: otherId }, { tenantId: otherId }, { userId: otherId }, { correlationId: 'trace' }, { schemaVersion: 2 }, { extra: true },
  { results: [] }, { results: [returnResult({ status: 'released', code: 201 })] }, { results: [returnResult({ extra: true })] },
  { results: [returnResult({ status: 'unconfirmed', code: 200 })] }, { results: [returnResult({ status: 'not_attempted', code: 409 })] },
  { results: [returnResult({ assignmentId: otherId })] }, { results: [returnResult({ poolId: otherId })] }])
('refuses malformed return receipts and consumes the preview after one POST: %j', async changes => {
  const client = await ready(); const preview = await client.previewLicenseReturns(userId);
  (api.post as jest.Mock).mockResolvedValue({ status: 200, data: returnReceipt(undefined, changes) });
  await expect(client.returnLicenses(preview, returnInput)).rejects.toThrow(); await expect(client.returnLicenses(preview, returnInput)).rejects.toThrow(); expect(api.post).toHaveBeenCalledTimes(1);
});
test.each(['reordered', 'released after failure', 'second failure', 'skipped first failure', 'all released 207', 'unconfirmed 200', 'wrong HTTP'])
('rejects invalid return stop/order semantics: %s', async scenario => {
  const client = await ready(); const results = threeReturns(); const preview = await client.previewLicenseReturns(userId); let status = 207;
  if (scenario === 'reordered') results.reverse();
  if (scenario === 'released after failure') results[2] = { ...results[2], status: 'released', code: 200 };
  if (scenario === 'second failure') results[2] = { ...results[2], status: 'unconfirmed', code: 409 };
  if (scenario === 'skipped first failure') results[1] = { ...results[1], status: 'not_attempted', code: null };
  if (scenario === 'all released 207') results.forEach(row => { row.status = 'released'; row.code = 200; });
  if (scenario === 'unconfirmed 200') status = 200;
  if (scenario === 'wrong HTTP') status = 201;
  (api.post as jest.Mock).mockResolvedValue({ status, data: returnReceipt(results) }); await expect(client.returnLicenses(preview, returnInput)).rejects.toThrow(); expect(api.post).toHaveBeenCalledTimes(1);
});
test.each([401, 403, 404, 409, 412, 428, 503])('native employee return %s never retries or refreshes to write', async status => {
  const client = await ready(); const preview = await client.previewLicenseReturns(userId); const error = { response: { status } };
  (api.post as jest.Mock).mockRejectedValue(error); (api.get as jest.Mock).mockClear();
  await expect(client.returnLicenses(preview, returnInput)).rejects.toBe(error); await expect(client.returnLicenses(preview, returnInput)).rejects.toThrow();
  expect(api.post).toHaveBeenCalledTimes(1); expect((api.get as jest.Mock).mock.calls.map(([url]) => url)).toEqual([base + '/capabilities']);
});
test.each(['preflight', 'response'])('fresh return authority at %s rejects actor, tenant or permission drift', async checkpoint => {
  for (const changes of [{ actorUserId: otherId }, { tenantId: otherId }, { permissions: ['company.apps.read'] }]) {
    const client = await ready(); const preview = await client.previewLicenseReturns(userId); (api.post as jest.Mock).mockClear();
    if (checkpoint === 'preflight') access = capabilities(changes);
    else (api.post as jest.Mock).mockImplementation(async () => { access = capabilities(changes); return { status: 200, data: returnReceipt() }; });
    await expect(client.returnLicenses(preview, returnInput)).rejects.toThrow(); expect(api.post).toHaveBeenCalledTimes(checkpoint === 'preflight' ? 0 : 1);
  }
});
test('employee return shares the existing serialized write guard', async () => {
  const client = await ready(); const preview = await client.previewLicenseReturns(userId); const delayed = deferred<any>(); (api.post as jest.Mock).mockReturnValue(delayed.promise);
  const operation = client.returnLicenses(preview, returnInput);
  await expect(client.returnLicenses(preview, returnInput)).rejects.toThrow(); await expect(client.create(values)).rejects.toThrow();
  delayed.resolve({ status: 200, data: returnReceipt() }); await operation; expect(api.post).toHaveBeenCalledTimes(1);
});
test.each(['abort', 'session', 'reload', 'dispose'])('late employee return after %s is never confirmed and cannot reuse snapshots', async action => {
  const client = await ready(); const preview = await client.previewLicenseReturns(userId); const controller = new AbortController(); const delayed = deferred<any>();
  (api.post as jest.Mock).mockReturnValue(delayed.promise); const operation = client.returnLicenses(preview, returnInput, controller.signal);
  for (let turn = 0; turn < 6; turn += 1) await Promise.resolve(); expect(api.post).toHaveBeenCalledTimes(1);
  if (action === 'abort') controller.abort();
  if (action === 'session') window.dispatchEvent(new Event('od:session-error'));
  if (action === 'reload') await client.reload();
  if (action === 'dispose') client.dispose();
  expect((api.post as jest.Mock).mock.calls[0][2].signal.aborted).toBe(true);
  delayed.resolve({ status: 200, data: returnReceipt() }); await expect(operation).rejects.toThrow();
  await expect(client.returnLicenses(preview, returnInput)).rejects.toThrow(); expect(api.post).toHaveBeenCalledTimes(1);
});
test('aborting a preview invalidates authority immediately even if the transport resolves late', async () => {
  const client = await ready(); const controller = new AbortController(); const delayed = deferred<any>();
  (api.get as jest.Mock).mockImplementation(url => url.endsWith('/license-returns') ? delayed.promise : getResponse(url));
  const operation = client.previewLicenseReturns(userId, 1, controller.signal); for (let turn = 0; turn < 6; turn += 1) await Promise.resolve(); controller.abort();
  await expect(client.list()).rejects.toThrow(); delayed.resolve({ status: 200, data: returnEnvelope }); await expect(operation).rejects.toThrow(); expect(api.post).not.toHaveBeenCalled();
});

async function editable() {
  const client = await ready(); const snapshot = await client.get(poolId);
  await client.editCapabilities(snapshot); return { client, snapshot };
}
test('editing explicitly attests one remembered pool, normalizes all fields and uses its exact BIGINT ETag once', async () => {
  const client = await ready(); record = cleanPool({ revision: '9007199254740993', usedSeats: 1, availableSeats: 1 });
  const snapshot = await client.get(poolId);
  expect((api.get as jest.Mock).mock.calls.some(([url]) => url.endsWith('/edit-capabilities'))).toBe(false);
  await client.editCapabilities(snapshot);
  const response = editResponse({ revision: '9007199254740994', usedSeats: 1, availableSeats: 2 });
  (api.patch as jest.Mock).mockResolvedValue(response);
  const input = { ...editInput, name: ' Updated App ', vendor: ' Example Vendor ', description: ' Local business app ', reason: ' Reviewed company license stock ' };
  expect(await client.edit(snapshot, input)).toEqual(response.data);
  expect(api.patch).toHaveBeenCalledWith(base + '/pools/' + poolId, editInput,
    { headers: { 'If-Match': '"company-pool-' + poolId + '-9007199254740993"' }, signal: expect.any(AbortSignal) });
  expect((api.get as jest.Mock).mock.calls.filter(([url]) => url.endsWith('/edit-capabilities'))).toEqual([
    [base + '/pools/' + poolId + '/edit-capabilities', { signal: expect.any(AbortSignal) }],
    [base + '/pools/' + poolId + '/edit-capabilities', { signal: expect.any(AbortSignal) }],
  ]);
  await expect(client.edit(snapshot, editInput)).rejects.toThrow(); expect(api.patch).toHaveBeenCalledTimes(1); expect(api.post).not.toHaveBeenCalled();
});
test.each([{ confirm: false }, { confirm: undefined }, { name: undefined }, { vendor: undefined }, { description: undefined }, { totalSeats: undefined },
  { name: 'bad\nname' }, { vendor: ' ' }, { description: 'bad\u0000description' }, { totalSeats: 0 }, { totalSeats: 10001 }, { totalSeats: 1.5 },
  { totalSeats: '3' }, { totalSeats: NaN }, { reason: 'short' }, { tenantId }, { poolId }, { revision: '2' }, { usedSeats: 0 }])
('edit input is complete and exact before any HTTP: %j', async changes => {
  const { client, snapshot } = await editable(); (api.get as jest.Mock).mockClear();
  await expect(client.edit(snapshot, Object.assign({}, editInput, changes))).rejects.toThrow();
  expect(api.get).not.toHaveBeenCalled(); expect(api.patch).not.toHaveBeenCalled();
});
test.each(['no-op', 'used floor'])('rejects %s without fetching or writing and never adjusts stock automatically', async scenario => {
  const client = await ready(); record = cleanPool({ usedSeats: 2, availableSeats: 0 }); const snapshot = await client.get(poolId); await client.editCapabilities(snapshot);
  (api.get as jest.Mock).mockClear();
  await expect(client.edit(snapshot, scenario === 'no-op' ? { ...values, name: ' Example App ', confirm: true } : { ...editInput, totalSeats: 1 })).rejects.toThrow();
  expect(api.get).not.toHaveBeenCalled(); expect(api.patch).not.toHaveBeenCalled(); expect(snapshot.usedSeats).toBe(2);
});
test.each(['no capability', 'clone', 'foreign client', 'expired', 'future', 'newer known pool', 'other write', 'max revision'])
('edit cannot accept %s snapshots', async scenario => {
  const client = await ready();
  if (scenario === 'max revision') record = cleanPool({ revision: '9223372036854775807' });
  let snapshot = await client.get(poolId);
  if (scenario === 'max revision') { await expect(client.editCapabilities(snapshot)).rejects.toThrow(); expect(api.patch).not.toHaveBeenCalled(); return; }
  if (scenario !== 'no capability') await client.editCapabilities(snapshot);
  if (scenario === 'clone') snapshot = { ...snapshot };
  if (scenario === 'future') snapshot = { ...snapshot, revision: '2' };
  if (scenario === 'foreign client') { const other = await ready(); await expect(other.edit(snapshot, editInput)).rejects.toThrow(); expect(api.patch).not.toHaveBeenCalled(); return; }
  if (scenario === 'expired') await client.reload();
  if (scenario === 'newer known pool') { record = cleanPool({ revision: '2' }); await client.get(poolId); }
  if (scenario === 'other write') { (api.post as jest.Mock).mockResolvedValue({ status: 201, data: cleanPool({ id: otherId }) }); await client.create(values); }
  await expect(client.edit(snapshot, editInput)).rejects.toThrow(); expect(api.patch).not.toHaveBeenCalled();
});
test.each([{ schemaVersion: 2 }, { companyPoolEditProtocol: 0 }, { companyPoolEditProtocol: undefined }, { companyPoolEditProtocol: 2 },
  { actorUserId: otherId }, { tenantId: otherId }, { poolId: otherId }, { poolRevision: '2' }, { poolRevision: 1 }, { poolRevision: '01' }, { supported: true }])
('pool edit capability fails closed for %j', async changes => {
  const client = await ready(); const snapshot = await client.get(poolId);
  (api.get as jest.Mock).mockImplementation(url => url.endsWith('/edit-capabilities')
    ? { status: 200, data: editCapabilities(changes), headers: { 'cache-control': 'no-store' } } : getResponse(url));
  await expect(client.editCapabilities(snapshot)).rejects.toThrow(); await expect(client.edit(snapshot, editInput)).rejects.toThrow(); expect(api.patch).not.toHaveBeenCalled();
});
test.each([{ status: 201 }, { headers: {} }, { headers: { 'cache-control': 'public' } }, { data: undefined }])
('pool edit capability requires 200, real protocol and no-store: %j', async changes => {
  const client = await ready(); const snapshot = await client.get(poolId);
  (api.get as jest.Mock).mockImplementation(url => url.endsWith('/edit-capabilities')
    ? { status: 200, data: editCapabilities(), headers: { 'cache-control': 'no-store' }, ...changes } : getResponse(url));
  await expect(client.editCapabilities(snapshot)).rejects.toThrow(); expect(api.patch).not.toHaveBeenCalled();
});
test.each(['before capability', 'before write', 'after write'])('edit retains fresh global authority %s', async checkpoint => {
  for (const changes of [{ actorUserId: otherId }, { tenantId: otherId }, { permissions: ['company.apps.read'] }, { permissions: ['company.apps.create'] }, { companyLicenseProtocol: 0 }]) {
    const client = await ready(); const snapshot = await client.get(poolId); (api.patch as jest.Mock).mockClear();
    if (checkpoint !== 'before capability') await client.editCapabilities(snapshot);
    if (checkpoint !== 'after write') access = capabilities(changes);
    else (api.patch as jest.Mock).mockImplementation(async () => { access = capabilities(changes); return editResponse(); });
    await expect(checkpoint === 'before capability' ? client.editCapabilities(snapshot) : client.edit(snapshot, editInput)).rejects.toThrow();
    expect(api.patch).toHaveBeenCalledTimes(checkpoint === 'after write' ? 1 : 0);
  }
});
test('edit repeats the actual pool protocol preflight immediately before PATCH', async () => {
  const { client, snapshot } = await editable();
  (api.get as jest.Mock).mockImplementation(url => url.endsWith('/edit-capabilities') ? Promise.reject({ response: { status: 409 } }) : getResponse(url));
  await expect(client.edit(snapshot, editInput)).rejects.toMatchObject({ response: { status: 409 } }); expect(api.patch).not.toHaveBeenCalled();
});
test.each([{ revision: '3' }, { revision: '1' }, { name: 'Wrong name' }, { vendor: 'Wrong vendor' }, { description: 'Wrong description' },
  { totalSeats: 4, availableSeats: 4 }, { usedSeats: 1, availableSeats: 2 }, { tenantId: otherId }, { id: otherId },
  { createdAt: '2026-10-18T10:00:00.000Z' }, { updatedAt: '2026-10-18T10:00:00.000Z' }, { allocationMode: 'provider' }, { extra: true }])
('malformed edit response never confirms success or permits reuse: %j', async changes => {
  const { client, snapshot } = await editable(); (api.patch as jest.Mock).mockResolvedValue(editResponse(changes));
  await expect(client.edit(snapshot, editInput)).rejects.toThrow(); await expect(client.edit(snapshot, editInput)).rejects.toThrow();
  expect(api.patch).toHaveBeenCalledTimes(1); await expect(client.list()).rejects.toThrow();
});
test.each([undefined, 'W/"company-pool-' + poolId + '-2"', '"company-pool-' + poolId + '-1"', '"other"'])
('edit requires the exact new strong response ETag: %j', async etag => {
  const { client, snapshot } = await editable(); (api.patch as jest.Mock).mockResolvedValue({ ...editResponse(), headers: { etag } });
  await expect(client.edit(snapshot, editInput)).rejects.toThrow(); expect(api.patch).toHaveBeenCalledTimes(1);
});
test.each([201, 204])('HTTP %s cannot confirm an edit', async status => {
  const { client, snapshot } = await editable(); (api.patch as jest.Mock).mockResolvedValue({ ...editResponse(), status });
  await expect(client.edit(snapshot, editInput)).rejects.toThrow(); expect(api.patch).toHaveBeenCalledTimes(1);
});
test.each([400, 401, 403, 404, 409, 412, 428, 503, 'timeout'])('edit failure %s is consumed without a retry or invented state', async failure => {
  const { client, snapshot } = await editable(); const error = failure === 'timeout' ? new Error('timeout') : { response: { status: failure } };
  (api.patch as jest.Mock).mockRejectedValue(error);
  await expect(client.edit(snapshot, editInput)).rejects.toBe(error); await expect(client.edit(snapshot, editInput)).rejects.toThrow();
  expect(api.patch).toHaveBeenCalledTimes(1); expect(companyApplicationsError(error)).toMatch(/neu laden/);
});
test('edits share the serialized writer with creation, assignment and returns', async () => {
  const { client, snapshot } = await editable(); const delayed = deferred<ReturnType<typeof editResponse>>(); (api.patch as jest.Mock).mockReturnValue(delayed.promise);
  const operation = client.edit(snapshot, editInput);
  await expect(client.edit(snapshot, editInput)).rejects.toThrow(); await expect(client.create(values)).rejects.toThrow();
  await expect(client.assign(snapshot, { userId, reason: values.reason, confirm: true })).rejects.toThrow();
  delayed.resolve(editResponse()); await operation; expect(api.patch).toHaveBeenCalledTimes(1); expect(api.post).not.toHaveBeenCalled();
});
test.each(['abort', 'session', 'reload', 'dispose'])('a pending edit after %s aborts and discards its late result', async action => {
  const { client, snapshot } = await editable(); const controller = new AbortController(); const delayed = deferred<ReturnType<typeof editResponse>>();
  (api.patch as jest.Mock).mockReturnValue(delayed.promise); const operation = client.edit(snapshot, editInput, controller.signal);
  for (let turn = 0; turn < 12; turn += 1) await Promise.resolve(); expect(api.patch).toHaveBeenCalledTimes(1);
  if (action === 'abort') controller.abort();
  if (action === 'session') window.dispatchEvent(new Event('od:session-error'));
  if (action === 'reload') await client.reload();
  if (action === 'dispose') client.dispose();
  expect((api.patch as jest.Mock).mock.calls[0][2].signal.aborted).toBe(true);
  delayed.resolve(editResponse()); await expect(operation).rejects.toThrow(); await expect(client.edit(snapshot, editInput)).rejects.toThrow(); expect(api.patch).toHaveBeenCalledTimes(1);
});
test('session loss during edit capability preflight prevents the pending PATCH', async () => {
  const { client, snapshot } = await editable(); const delayed = deferred<Awaited<ReturnType<typeof getResponse>>>();
  (api.get as jest.Mock).mockImplementation(url => url.endsWith('/edit-capabilities') ? delayed.promise : getResponse(url));
  const operation = client.edit(snapshot, editInput);
  for (let turn = 0; turn < 8; turn += 1) await Promise.resolve();
  window.dispatchEvent(new Event('od:session-error'));
  delayed.resolve(await getResponse(base + '/pools/' + poolId + '/edit-capabilities'));
  await expect(operation).rejects.toThrow(); expect(api.patch).not.toHaveBeenCalled();
});
test.each([{ beforeRevision: null }, { beforeRevision: '0' }, { userId }, { afterRevision: '3' }])
('pool update history rejects inconsistent evidence: %j', async changes => {
  const client = await ready(); historyEnvelope.events = [event({ type: 'app.license.pool.updated', beforeRevision: '1', afterRevision: '2', ...changes })];
  await expect(client.history(poolId)).rejects.toThrow();
});
test('pool update history accepts null target and an exact positive BIGINT increment', async () => {
  const client = await ready(); historyEnvelope.events = [event({ type: 'app.license.pool.updated', beforeRevision: '9007199254740993', afterRevision: '9007199254740994' })];
  expect((await client.history(poolId)).events).toEqual(historyEnvelope.events);
});
