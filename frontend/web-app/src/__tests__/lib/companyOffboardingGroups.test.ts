import { CompanyOffboardingGroupsClient, offboardingGroupsReason } from '@/lib/companyOffboardingGroups';
import { userId, workflowId, otherId, reason } from '../fixtures/companyOffboarding';
import { groupsBase, groupsBinding, groupFixture, groupsPreviewFixture, groupsHistoryFixture, groupReceiptFixture, groupResultFixture, groupsOutcomeFixture, deferred } from '../fixtures/companyOffboardingGroups';

const mockGet = jest.fn();
const mockPost = jest.fn();
jest.mock('@/lib/api', () => ({ api: { get: (...args: unknown[]) => mockGet(...args), post: (...args: unknown[]) => mockPost(...args) } }));
let preview: unknown;
let history: unknown;
const clients: CompanyOffboardingGroupsClient[] = [];
function client(binding = groupsBinding) { const current = new CompanyOffboardingGroupsClient(binding); clients.push(current); return current; }
async function ready(current = client()) { const snapshot = await current.preview(); await current.history(); return { current, snapshot }; }
beforeEach(() => {
  jest.resetAllMocks(); preview = groupsPreviewFixture(); history = groupsHistoryFixture();
  mockGet.mockImplementation(async (url: string) => {
    if (url === groupsBase) return { status: 200, data: preview };
    if (url === groupsBase + '/history') return { status: 200, data: history };
    throw new Error('Unexpected endpoint ' + url);
  });
  mockPost.mockResolvedValue({ status: 200, data: groupsOutcomeFixture() });
});
afterEach(() => { clients.splice(0).forEach(current => current.dispose()); });

test('does not fetch on construction and reads exact bound paths, pages and protocol', async () => {
  const current = client(); expect(mockGet).not.toHaveBeenCalled();
  const snapshot = await current.preview(); await current.history();
  expect(mockGet.mock.calls.map(([url]) => url)).toEqual([groupsBase, groupsBase + '/history']);
  expect(mockGet).toHaveBeenNthCalledWith(1, groupsBase, { params: { workflowId, page: 1, limit: 25 }, signal: expect.any(AbortSignal) });
  expect(mockGet).toHaveBeenNthCalledWith(2, groupsBase + '/history', { params: { workflowId, page: 1, limit: 25 }, signal: expect.any(AbortSignal) });
  expect(snapshot.groups[0].groupRevision).toBe('9007199254740993'); expect(Object.isFrozen(snapshot.groups[0])).toBe(true);
  expect(Object.isFrozen(snapshot.target)).toBe(true); expect(mockPost).not.toHaveBeenCalled();
});
test('writes only the remembered displayed manifest and exact normalized body, then consumes authorization', async () => {
  const { current, snapshot } = await ready();
  const result = await current.remove(snapshot, { reason: '  ' + reason + '  ', confirm: true });
  expect(result.results[0].operationId).toBe(groupResultFixture().operationId);
  expect(mockPost).toHaveBeenCalledWith(groupsBase, {
    workflowId, eligibilityRevision: '8', reason, confirm: true,
    memberships: [{ groupId: groupFixture().groupId, groupRevision: '9007199254740993', membershipId: groupFixture().membershipId }],
  }, { signal: expect.any(AbortSignal) });
  expect(mockGet).toHaveBeenCalledTimes(2);
  await expect(current.remove(snapshot, { reason, confirm: true })).rejects.toThrow(); expect(mockPost).toHaveBeenCalledTimes(1);
  const fresh = await current.preview();
  await expect(current.remove(fresh, { reason, confirm: true })).rejects.toThrow(); expect(mockPost).toHaveBeenCalledTimes(1);
  const reloaded = await ready(current); await current.remove(reloaded.snapshot, { reason, confirm: true }); expect(mockPost).toHaveBeenCalledTimes(2);
});
test('retains the opaque original parent and negative epoch even if caller props are mutated', async () => {
  const binding = { ...groupsBinding, eligibilityRevision: '9007199254740993' };
  const current = client(binding); binding.workflowId = otherId; binding.eligibilityRevision = '9007199254740994';
  preview = groupsPreviewFixture({ target: { enabled: false, eligibilityRevision: '9007199254740993' } });
  history = groupsHistoryFixture({ target: { enabled: false, eligibilityRevision: '9007199254740993' } });
  const { snapshot } = await ready(current); await current.remove(snapshot, { reason, confirm: true });
  expect(mockPost.mock.calls[0][1]).toEqual(expect.objectContaining({ workflowId, eligibilityRevision: '9007199254740993' }));
});
test.each([
  ['schema', { schemaVersion: 2 }], ['missing protocol', { companyOffboardingGroupsProtocol: undefined }], ['old protocol', { companyOffboardingGroupsProtocol: 0 }],
  ['actor', { actorUserId: otherId }], ['tenant', { tenantId: otherId }], ['parent', { workflowId: otherId }], ['user', { userId: otherId }],
  ['positive target', { target: { enabled: true, eligibilityRevision: '8' } }], ['other epoch', { target: { enabled: false, eligibilityRevision: '9' } }],
  ['unknown target field', { target: { enabled: false, eligibilityRevision: '8', deleted: false } }],
  ['future bigint epoch', { target: { enabled: false, eligibilityRevision: '9223372036854775808' } }],
  ['bad total', { total: 2 }], ['unsafe total', { total: Number.MAX_SAFE_INTEGER + 1 }], ['wrong page', { page: 2 }], ['other limit', { limit: 24 }],
  ['extra field', { bearer: 'forbidden' }], ['duplicate groups', { groups: [groupFixture(), groupFixture()], total: 2 }],
  ['duplicate link', { groups: [groupFixture(), groupFixture(1, { membershipId: groupFixture().membershipId })], total: 2 }],
  ['unknown row field', { groups: [groupFixture(0, { automatic: true })] }],
  ['missing link', { groups: [groupFixture(0, { membershipId: undefined })] }], ['empty name', { groups: [groupFixture(0, { name: ' ' })] }],
  ['control name', { groups: [groupFixture(0, { name: 'Gruppe\nName' })] }], ['future bigint', { groups: [groupFixture(0, { groupRevision: '9223372036854775808' })] }],
  ['leading zero', { groups: [groupFixture(0, { groupRevision: '01' })] }], ['numeric version', { groups: [groupFixture(0, { groupRevision: 1 })] }],
  ['26 rows', { groups: Array.from({ length: 26 }, (_, index) => groupFixture(index)), total: 26 }],
])('fails closed for %s preview without alternate endpoints', async (_label, changes) => {
  preview = groupsPreviewFixture(changes); const current = client();
  await expect(current.preview()).rejects.toThrow(); expect(mockGet).toHaveBeenCalledTimes(1); expect(mockPost).not.toHaveBeenCalled();
});
test.each([0, -1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1])('rejects nonpositive or unsafe page %s before GET', async page => {
  const current = client(); await expect(current.preview(page)).rejects.toThrow(); await expect(current.history(page)).rejects.toThrow(); expect(mockGet).not.toHaveBeenCalled();
});
test('supports exact 25-row pages and empty later pages without treating them as global completion', async () => {
  preview = groupsPreviewFixture({ groups: Array.from({ length: 25 }, (_, index) => groupFixture(index)), total: 26 });
  const current = client(); expect((await current.preview()).groups).toHaveLength(25);
  preview = groupsPreviewFixture({ groups: [groupFixture(25)], total: 26, page: 2 });
  expect((await current.preview(2)).groups[0].groupId).toBe(groupFixture(25).groupId);
  expect(mockGet).toHaveBeenLastCalledWith(groupsBase, { params: { workflowId, page: 2, limit: 25 }, signal: expect.any(AbortSignal) });
  preview = groupsPreviewFixture({ groups: [], total: 26, page: 3 }); const empty = await current.preview(3); await current.history();
  await expect(current.remove(empty, { reason, confirm: true })).rejects.toThrow(); expect(mockPost).not.toHaveBeenCalled();
});
test('rejects forged snapshots, substituted future revisions and stale previews', async () => {
  const { current, snapshot } = await ready();
  await expect(current.remove({ ...snapshot }, { reason, confirm: true })).rejects.toThrow();
  const fresh = await ready(current);
  await expect(current.remove({ ...fresh.snapshot, groups: [{ ...fresh.snapshot.groups[0], groupRevision: '9223372036854775807' }] }, { reason, confirm: true })).rejects.toThrow();
  await ready(current); await expect(current.remove(snapshot, { reason, confirm: true })).rejects.toThrow(); expect(mockPost).not.toHaveBeenCalled();
});
test('history alone and a preview without fresh history cannot authorize a write', async () => {
  const current = client(); await current.history(); const snapshot = await current.preview();
  await expect(current.remove(snapshot, { reason, confirm: true })).rejects.toThrow(); expect(mockPost).not.toHaveBeenCalled();
});
test.each(['kurz', 'x'.repeat(501), '\n' + reason, reason + '\u007f', reason + '\u0085'])('rejects invalid reason %# before POST', async value => {
  const { current, snapshot } = await ready(); await expect(current.remove(snapshot, { reason: value, confirm: true })).rejects.toThrow(); expect(mockPost).not.toHaveBeenCalled();
});
test('reason normalization counts Unicode characters and rejects extra confirmation fields', async () => {
  expect(offboardingGroupsReason('😀'.repeat(500))).toBe('😀'.repeat(500)); expect(offboardingGroupsReason('  ' + reason + '  ')).toBe(reason);
  const { current, snapshot } = await ready();
  const confirmation: { reason: string; confirm: true; token: string } = { reason, confirm: true, token: 'forbidden' };
  await expect(current.remove(snapshot, confirmation)).rejects.toThrow(); expect(mockPost).not.toHaveBeenCalled();
});
test.each([false, undefined, 1])('requires exact explicit confirm true: %s', async confirm => {
  const { current, snapshot } = await ready();
  await expect(Reflect.apply(current.remove, current, [snapshot, { reason, confirm }])).rejects.toThrow(); expect(mockPost).not.toHaveBeenCalled();
});
test('accepts retained original already_removed operations and immutable pending history receipts', async () => {
  history = groupsHistoryFixture({ receipts: [groupReceiptFixture()], total: 1 });
  const { current, snapshot } = await ready(); mockPost.mockResolvedValue({ status: 200, data: groupsOutcomeFixture({ results: [groupResultFixture(0, { status: 'already_removed' })] }) });
  expect((await current.remove(snapshot, { reason, confirm: true })).results[0].operationId).toBe(groupReceiptFixture().operationId);
  expect((await current.history()).receipts[0].membershipId).toBe(snapshot.groups[0].membershipId);
  history = groupsHistoryFixture({ receipts: [groupReceiptFixture(0, { operationId: otherId })], total: 1 });
  await expect(current.history()).rejects.toThrow(); expect(mockPost).toHaveBeenCalledTimes(1);
});
test.each([
  ['foreign parent', { workflowId: otherId }], ['foreign tenant', { tenantId: otherId }], ['foreign actor', { actorUserId: otherId }], ['foreign user', { userId: otherId }],
  ['epoch', { target: { enabled: false, eligibilityRevision: '9' } }], ['old history protocol', { events: [] }], ['page', { page: 2 }], ['limit', { limit: 26 }],
  ['unconfirmed operation', { receipts: [groupReceiptFixture(0, { operationId: null })], total: 1 }],
  ['unchanged revision', { receipts: [groupReceiptFixture(0, { afterGroupRevision: '9007199254740993' })], total: 1 }],
  ['future revision', { receipts: [groupReceiptFixture(0, { afterGroupRevision: '9223372036854775808' })], total: 1 }],
  ['self actor', { receipts: [groupReceiptFixture(0, { actorUserId: userId })], total: 1 }], ['wrong delivery', { receipts: [groupReceiptFixture(0, { deliveryStatus: 'delivered' })], total: 1 }],
  ['untrimmed reason', { receipts: [groupReceiptFixture(0, { reason: ' ' + reason })], total: 1 }], ['invalid date', { receipts: [groupReceiptFixture(0, { createdAt: 'yesterday' })], total: 1 }],
  ['duplicate operation', { receipts: [groupReceiptFixture(), groupReceiptFixture(1, { operationId: groupReceiptFixture().operationId })], total: 2 }],
  ['duplicate link', { receipts: [groupReceiptFixture(), groupReceiptFixture(1, { membershipId: groupReceiptFixture().membershipId })], total: 2 }],
])('rejects %s history and removes write authorization', async (_label, changes) => {
  const current = client(); const snapshot = await current.preview(); history = groupsHistoryFixture(changes);
  await expect(current.history()).rejects.toThrow(); await expect(current.remove(snapshot, { reason, confirm: true })).rejects.toThrow(); expect(mockPost).not.toHaveBeenCalled();
});
test('207 confirms the original prefix, first failure and untouched remaining membership in exact order', async () => {
  preview = groupsPreviewFixture({ groups: [groupFixture(), groupFixture(1), groupFixture(2)], total: 3 });
  const { current, snapshot } = await ready();
  mockPost.mockResolvedValue({ status: 207, data: groupsOutcomeFixture({ results: [groupResultFixture(), groupResultFixture(1, { status: 'unconfirmed', code: 412, operationId: null }), groupResultFixture(2, { status: 'not_attempted', code: null, operationId: null })] }) });
  const result = await current.remove(snapshot, { reason, confirm: true });
  expect(result.results.map(row => row.status)).toEqual(['removed', 'unconfirmed', 'not_attempted']);
  expect(mockGet).toHaveBeenCalledTimes(2); await expect(current.remove(snapshot, { reason, confirm: true })).rejects.toThrow(); expect(mockPost).toHaveBeenCalledTimes(1);
});
test.each([
  ['foreign actor', 200, { actorUserId: otherId }], ['foreign tenant', 200, { tenantId: otherId }], ['foreign parent', 200, { workflowId: otherId }], ['foreign user', 200, { userId: otherId }],
  ['wrong schema', 200, { schemaVersion: 2 }], ['extra field', 200, { complete: true }], ['no correlation', 200, { correlationId: undefined }],
  ['empty results', 200, { results: [] }], ['extra result', 200, { results: [groupResultFixture(), groupResultFixture(1)] }],
  ['other group', 200, { results: [groupResultFixture(1)] }], ['other link', 200, { results: [groupResultFixture(0, { membershipId: otherId })] }],
  ['null confirmed operation', 200, { results: [groupResultFixture(0, { operationId: null })] }], ['fake operation', 200, { results: [groupResultFixture(0, { operationId: 'not-an-operation' })] }],
  ['confirmed failure code', 200, { results: [groupResultFixture(0, { code: 503 })] }], ['already removed no operation', 200, { results: [groupResultFixture(0, { status: 'already_removed', operationId: null })] }],
  ['200 unconfirmed', 200, { results: [groupResultFixture(0, { status: 'unconfirmed', code: 503, operationId: null })] }],
  ['207 all confirmed', 207, {}], ['207 missing code', 207, { results: [groupResultFixture(0, { status: 'unconfirmed', code: null, operationId: null })] }],
  ['207 unknown operation', 207, { results: [groupResultFixture(0, { status: 'unconfirmed', code: 503 })] }],
  ['207 skipped first', 207, { results: [groupResultFixture(0, { status: 'not_attempted', code: null, operationId: null })] }], ['unexpected status', 201, {}],
])('rejects %s outcome without automatic retry or reads', async (_label, status, changes) => {
  const { current, snapshot } = await ready(); mockPost.mockResolvedValue({ status, data: groupsOutcomeFixture(changes) });
  await expect(current.remove(snapshot, { reason, confirm: true })).rejects.toThrow();
  await expect(current.remove(snapshot, { reason, confirm: true })).rejects.toThrow(); expect(mockPost).toHaveBeenCalledTimes(1); expect(mockGet).toHaveBeenCalledTimes(2);
});
test.each([
  [groupResultFixture(1), groupResultFixture()],
  [groupResultFixture(), groupResultFixture(1, { operationId: groupResultFixture().operationId })],
  [groupResultFixture(0, { status: 'unconfirmed', code: 503, operationId: null }), groupResultFixture(1)],
  [groupResultFixture(0, { status: 'unconfirmed', code: 503, operationId: null }), groupResultFixture(1, { status: 'unconfirmed', code: 503, operationId: null })],
])('rejects reordered, duplicate or continued-after-failure results %#', async (first, second) => {
  preview = groupsPreviewFixture({ groups: [groupFixture(), groupFixture(1)], total: 2 });
  const { current, snapshot } = await ready(); mockPost.mockResolvedValue({ status: 207, data: groupsOutcomeFixture({ results: [first, second] }) });
  await expect(current.remove(snapshot, { reason, confirm: true })).rejects.toThrow(); expect(mockPost).toHaveBeenCalledTimes(1);
});
test.each([401, 403, 404, 409, 412, 428, 503])('source denial %s consumes authorization without retries', async status => {
  const { current, snapshot } = await ready(); mockPost.mockRejectedValue({ response: { status } });
  await expect(current.remove(snapshot, { reason, confirm: true })).rejects.toEqual({ response: { status } });
  await expect(current.remove(snapshot, { reason, confirm: true })).rejects.toThrow(); expect(mockPost).toHaveBeenCalledTimes(1); expect(mockGet).toHaveBeenCalledTimes(2);
});
test('external abort rejects a late preview and never authorizes its snapshot', async () => {
  const current = client(); const pending = deferred<{ status: number; data: unknown }>(); const controller = new AbortController();
  mockGet.mockReturnValue(pending.promise); const reading = current.preview(1, controller.signal); const rejected = expect(reading).rejects.toThrow();
  controller.abort(); expect(mockGet.mock.calls[0][1].signal.aborted).toBe(true);
  pending.resolve({ status: 200, data: groupsPreviewFixture() }); await rejected; expect(mockPost).not.toHaveBeenCalled();
});
test('a superseded read cannot invalidate the latest generation or authorize old rows', async () => {
  const current = client(); const pending = deferred<{ status: number; data: unknown }>(); mockGet.mockImplementationOnce(() => pending.promise);
  const oldRead = current.preview(); const rejected = expect(oldRead).rejects.toThrow(); const { snapshot } = await ready(current);
  expect(mockGet.mock.calls[0][1].signal.aborted).toBe(true); pending.resolve({ status: 200, data: groupsPreviewFixture() }); await rejected;
  await current.remove(snapshot, { reason, confirm: true }); expect(mockPost).toHaveBeenCalledTimes(1);
});
test('session invalidation aborts a writer and ignores a late committed reply', async () => {
  const { current, snapshot } = await ready(); const pending = deferred<{ status: number; data: unknown }>(); mockPost.mockReturnValue(pending.promise);
  const writing = current.remove(snapshot, { reason, confirm: true }); const rejected = expect(writing).rejects.toThrow();
  window.dispatchEvent(new CustomEvent('od:session-error')); expect(mockPost.mock.calls[0][2].signal.aborted).toBe(true);
  pending.resolve({ status: 200, data: groupsOutcomeFixture() }); await rejected;
  await expect(current.remove(snapshot, { reason, confirm: true })).rejects.toThrow(); expect(mockPost).toHaveBeenCalledTimes(1);
});
test('serializes writers and refuses reads during a writer without cancelling its valid reply', async () => {
  const { current, snapshot } = await ready(); const pending = deferred<{ status: number; data: unknown }>(); mockPost.mockReturnValue(pending.promise);
  const writing = current.remove(snapshot, { reason, confirm: true });
  await expect(current.remove(snapshot, { reason, confirm: true })).rejects.toThrow(); await expect(current.preview()).rejects.toThrow(); await expect(current.history()).rejects.toThrow();
  expect(mockPost.mock.calls[0][2].signal.aborted).toBe(false); pending.resolve({ status: 200, data: groupsOutcomeFixture() }); await writing; expect(mockPost).toHaveBeenCalledTimes(1);
});
test.each([
  { ...groupsBinding, actorUserId: userId }, { ...groupsBinding, tenantId: 'not-a-tenant' }, { ...groupsBinding, workflowId: '' },
  { ...groupsBinding, eligibilityRevision: '01' }, { ...groupsBinding, eligibilityRevision: '9223372036854775808' },
])('rejects invalid immutable binding before requests %#', binding => {
  expect(() => client(binding)).toThrow(); expect(mockGet).not.toHaveBeenCalled(); expect(mockPost).not.toHaveBeenCalled();
});
