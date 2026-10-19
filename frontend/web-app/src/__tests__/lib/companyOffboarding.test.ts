import { api } from '@/lib/api';
import { CompanyOffboardingClient, offboardingEtag, offboardingReason, offboardingTargetChanged } from '@/lib/companyOffboarding';
import { actorUserId, tenantId, userId, workflowId, poolId, assignmentId, grantId, otherId, context, base, jobs, reason, requestedRevision, capabilitiesFixture, previewFixture, itemFixture, jobFixture, pendingFixture, completedFixture, summaryFixture, queueFixture, historyFixture } from '../fixtures/companyOffboarding';

jest.mock('@/lib/api', () => ({ api: { get: jest.fn(), post: jest.fn() } }));

let access: any;
let record: any;
let preview: any;
let queue: any;
let events: any;
const clients: CompanyOffboardingClient[] = [];
function newClient() { const client = new CompanyOffboardingClient(context); clients.push(client); return client; }
async function ready() { const client = newClient(); await client.reload(); return client; }
function deferred<Value>() {
  let resolve: (value: Value) => void;
  const promise = new Promise<Value>(complete => { resolve = complete; });
  return { promise, resolve: (value: Value) => resolve(value) };
}
async function getResponse(url: string) {
  if (url === jobs + '/capabilities') return { status: 200, data: access };
  if (url === base + '/users/' + userId + '/offboarding-preview') return { status: 200, data: preview };
  if (url === jobs + '/' + workflowId) return { status: 200, data: record, headers: { etag: offboardingEtag(record.workflow) } };
  if (url === jobs) return { status: 200, data: queue };
  if (url === jobs + '/' + workflowId + '/history') return { status: 200, data: events };
  throw new Error('Unexpected endpoint ' + url);
}
beforeEach(() => {
  jest.restoreAllMocks(); jest.resetAllMocks(); window.localStorage.clear();
  Object.defineProperty(window.crypto, 'randomUUID', { configurable: true, value: jest.fn(() => workflowId) });
  access = capabilitiesFixture(); record = jobFixture(); preview = previewFixture(); queue = queueFixture(); events = historyFixture();
  (api.get as jest.Mock).mockImplementation(getResponse);
});
afterEach(() => clients.splice(0).forEach(client => client.dispose()));

test('creates one durable intent, preserves exact bigint strings and exposes partial completion', async () => {
  const client = await ready(); const snapshot = await client.preview(userId);
  (api.post as jest.Mock).mockResolvedValue({ status: 201, data: record });
  const result = await client.create(snapshot, { reason: ' ' + reason + ' ', confirm: true });
  expect(result.workflow.phase).toBe('licenses'); expect(result.workflow.completedLicenses).toBe(25);
  expect(api.post).toHaveBeenCalledWith(jobs, { workflowId, userId, userRevision: requestedRevision, eligibilityRevision: '7', reason, confirm: true }, { signal: expect.any(AbortSignal) });
  expect(client.knownIdRecovery).toBeNull(); expect(window.localStorage.length).toBe(0);
  await expect(client.continue(result, { reason, confirm: true })).rejects.toThrow();
  expect(api.post).toHaveBeenCalledTimes(1);
});
test('GET with exact ETag authorizes one explicit batch, never an automatic continuation', async () => {
  const client = await ready(); const snapshot = await client.get(workflowId);
  (api.post as jest.Mock).mockResolvedValue({ status: 200, data: completedFixture() });
  const result = await client.continue(snapshot, { reason, confirm: true });
  expect(result.workflow.phase).toBe('completed_local');
  expect(api.post).toHaveBeenCalledWith(jobs + '/' + workflowId + '/continue', { confirm: true, reason, userRevision: requestedRevision,
    assignments: [{ poolId, assignmentId, poolRevision: '9007199254740995' }] }, { headers: { 'If-Match': offboardingEtag(snapshot.workflow) }, signal: expect.any(AbortSignal) });
  await expect(client.continue(snapshot, { reason, confirm: true })).rejects.toThrow(); expect(api.post).toHaveBeenCalledTimes(1);
});
test('continuation rejects an edited immutable intent reason without POST', async () => {
  const client = await ready(); const snapshot = await client.get(workflowId);
  await expect(client.continue(snapshot, { reason: 'Eine andere Begründung für Fortsetzung', confirm: true })).rejects.toThrow(); expect(api.post).not.toHaveBeenCalled();
});
test('lost create reply keeps only a UUID across invalidation and a new login client; recovery uses GET', async () => {
  const client = await ready(); const snapshot = await client.preview(userId);
  (api.post as jest.Mock).mockRejectedValue(new Error('Lost ACK'));
  await expect(client.create(snapshot, { reason, confirm: true })).rejects.toThrow();
  client.invalidate(); expect(client.knownIdRecovery).toBe(workflowId);
  expect(window.localStorage.getItem(window.localStorage.key(0))).toBe(workflowId);
  const recovered = await ready(); expect(recovered.knownIdRecovery).toBe(workflowId);
  await recovered.get(workflowId); expect(recovered.knownIdRecovery).toBeNull(); expect(api.post).toHaveBeenCalledTimes(1);
});
test('retains known ID if actor changes after a committed POST', async () => {
  const client = await ready(); const snapshot = await client.preview(userId);
  (api.post as jest.Mock).mockImplementation(async () => { access = capabilitiesFixture({ actorUserId: otherId }); return { status: 201, data: record }; });
  await expect(client.create(snapshot, { reason, confirm: true })).rejects.toThrow();
  expect(client.knownIdRecovery).toBe(workflowId); expect(api.post).toHaveBeenCalledTimes(1);
  await expect(client.list()).rejects.toThrow();
});
test('unacknowledged account disable always recovers with requestedRevision, even if now disabled and profile changed', async () => {
  record = pendingFixture({ phase: 'paused', failure: { code: 503, step: 'account' } });
  record.currentTarget = { enabled: false, deleted: false, eligibilityRevision: '8' };
  const client = await ready(); const snapshot = await client.get(workflowId);
  (api.post as jest.Mock).mockResolvedValue({ status: 200, data: jobFixture({ revision: '3' }) });
  await client.continue(snapshot, { reason, confirm: true });
  expect((api.post as jest.Mock).mock.calls[0][1]).toEqual({ reason, confirm: true, userRevision: requestedRevision, assignments: [] });
  expect((api.get as jest.Mock).mock.calls.some(([url]) => url.endsWith('/offboarding-preview'))).toBe(false);
});
test('only explicit 412/account permits a newly approved profile revision with the same eligibility snapshot', async () => {
  record = pendingFixture({ phase: 'paused', failure: { code: 412, step: 'account' } });
  preview = previewFixture({ userRevision: '9007199254740999' });
  const client = await ready(); const snapshot = await client.get(workflowId); const freshPreview = await client.preview(userId);
  const result = jobFixture({ revision: '3', requestedRevision: preview.user.userRevision });
  result.workflow.checkpoint.beforeRevision = preview.user.userRevision; result.workflow.checkpoint.afterRevision = '9007199254741000';
  (api.post as jest.Mock).mockResolvedValue({ status: 200, data: result });
  await client.continue(snapshot, { reason, confirm: true }, freshPreview);
  expect((api.post as jest.Mock).mock.calls[0][1].userRevision).toBe('9007199254740999');
});
test.each(['missing', 'new-generation'])('412/account blocks %s preview before POST', async mode => {
  record = pendingFixture({ phase: 'paused', failure: { code: 412, step: 'account' } });
  const client = await ready(); const snapshot = await client.get(workflowId);
  preview = previewFixture({ eligibilityRevision: '9' });
  const freshPreview = mode === 'missing' ? undefined : await client.preview(userId);
  await expect(client.continue(snapshot, { reason, confirm: true }, freshPreview)).rejects.toThrow(); expect(api.post).not.toHaveBeenCalled();
});
test('normal account recovery rejects a substituted fresh preview', async () => {
  record = pendingFixture({ phase: 'paused', failure: { code: 503, step: 'account' } });
  const client = await ready(); const snapshot = await client.get(workflowId); const freshPreview = await client.preview(userId);
  await expect(client.continue(snapshot, { reason, confirm: true }, freshPreview)).rejects.toThrow(); expect(api.post).not.toHaveBeenCalled();
});
test.each(['account', 'verify'])('a confirmed 409/%s without a checkpoint blocks a future account incarnation', async step => {
  record = pendingFixture({ phase: 'paused', failure: { code: 409, step } }); record.currentTarget.eligibilityRevision = '9';
  const client = await ready(); const snapshot = await client.get(workflowId);
  expect(offboardingTargetChanged(snapshot)).toBe(true);
  await expect(client.continue(snapshot, { reason, confirm: true })).rejects.toThrow(); expect(api.post).not.toHaveBeenCalled();
});
test('paused license review uses only the same captured IDs and explicitly retrieved current versions', async () => {
  record = jobFixture({ phase: 'paused', failure: { code: 412, step: 'licenses' }, reviewAssignments: [itemFixture({ poolRevision: '9007199254740999' })] });
  const client = await ready(); const snapshot = await client.get(workflowId);
  (api.post as jest.Mock).mockResolvedValue({ status: 200, data: completedFixture() });
  await client.continue(snapshot, { reason, confirm: true });
  expect((api.post as jest.Mock).mock.calls[0][1].assignments).toEqual([{ poolId, assignmentId, poolRevision: '9007199254740999' }]);
});
test.each([401, 403, 409, 412, 428, 503])('source %s withholds old data, retains ID and requires GET before another write', async status => {
  const client = await ready(); const snapshot = await client.get(workflowId);
  (api.post as jest.Mock).mockRejectedValue({ response: { status, data: completedFixture() } });
  await expect(client.continue(snapshot, { reason, confirm: true })).rejects.toEqual(expect.objectContaining({ response: expect.objectContaining({ status }) }));
  expect(client.knownIdRecovery).toBe(workflowId);
  await expect(client.continue(snapshot, { reason, confirm: true })).rejects.toThrow(); expect(api.post).toHaveBeenCalledTimes(1);
  await client.reload(); await client.get(workflowId); expect(api.post).toHaveBeenCalledTimes(1);
});
test('completed history can be read after reactivation but continuation stops on any checkpoint generation change', async () => {
  record = completedFixture(); record.currentTarget = { enabled: true, deleted: false, eligibilityRevision: '9' };
  events = historyFixture(record); const client = await ready(); const snapshot = await client.get(workflowId);
  expect(offboardingTargetChanged(snapshot)).toBe(true); expect((await client.history(workflowId)).events).toHaveLength(1);
  await expect(client.continue(snapshot, { reason, confirm: true })).rejects.toThrow(); expect(api.post).not.toHaveBeenCalled();
});
test.each([{ enabled: true }, { eligibilityRevision: '9' }, { deleted: true }])('blocks changed checkpoint target: %j', async target => {
  record = jobFixture({}, target); const client = await ready(); const snapshot = await client.get(workflowId);
  await expect(client.continue(snapshot, { reason, confirm: true })).rejects.toThrow(); expect(api.post).not.toHaveBeenCalled();
});
test.each([{ schemaVersion: 2 }, { companyOffboardingProtocol: 0 }, { companyOffboardingProtocol: undefined }, { actorUserId: otherId }, { tenantId: otherId }, { scope: 'devices' }, { requiresFreshMfa: false }, { bearer: 'forbidden' }])('rejects foreign or unsupported capabilities %j', async changes => {
  access = capabilitiesFixture(changes); const client = newClient(); await expect(client.reload()).rejects.toThrow(); await expect(client.list()).rejects.toThrow(); expect(api.post).not.toHaveBeenCalled();
});
test.each([
  (value: any) => { value.tenantId = otherId; },
  (value: any) => { value.actorUserId = otherId; },
  (value: any) => { value.workflow.userId = actorUserId; },
  (value: any) => { value.workflow.revision = '9223372036854775808'; },
  (value: any) => { value.workflow.requestedRevision = '01'; },
  (value: any) => { value.workflow.nextAssignments.push(itemFixture()); },
  (value: any) => { value.workflow.nextAssignments[0].token = 'forbidden'; },
  (value: any) => { value.workflow.checkpoint.operationId = null; },
  (value: any) => { value.workflow.checkpoint.afterRevision = requestedRevision; },
  (value: any) => { value.workflow.checkpoint.userId = otherId; },
  (value: any) => { value.workflow.checkpoint.actorUserId = userId; },
  (value: any) => { value.workflow.checkpoint.action = 'already_disabled'; },
  (value: any) => { value.workflow.phase = 'completed_local'; },
  (value: any) => { value.workflow.completedLicenses = 27; },
  (value: any) => { value.workflow.reviewAssignments = [itemFixture()]; },
  (value: any) => { value.currentTarget.profile = {}; },
])('rejects malformed or contradictory job boundary %#', async mutate => {
  mutate(record); const client = await ready(); await expect(client.get(workflowId)).rejects.toThrow(); expect(api.post).not.toHaveBeenCalled();
});
test.each(['assignmentId', 'poolId', 'grantId'])('rejects paused review substituting captured %s', async field => {
  record = jobFixture({ phase: 'paused', failure: { code: 412, step: 'licenses' }, reviewAssignments: [itemFixture({ [field]: otherId })] });
  const client = await ready(); await expect(client.get(workflowId)).rejects.toThrow();
});
test('requires exact GET status and ETag', async () => {
  const client = await ready(); (api.get as jest.Mock).mockImplementation(async url => url === jobs + '/' + workflowId ? { status: 200, data: record, headers: { etag: 'W/' + offboardingEtag(record.workflow) } } : getResponse(url));
  await expect(client.get(workflowId)).rejects.toThrow(); expect(api.post).not.toHaveBeenCalled();
});
test('honors immutable current snapshots and rejects a known newer journal revision', async () => {
  const client = await ready(); const snapshot = await client.get(workflowId);
  expect(Object.isFrozen(snapshot.workflow.nextAssignments[0])).toBe(true);
  queue = queueFixture(jobFixture({ revision: '3' })); await client.list();
  await expect(client.continue(snapshot, { reason, confirm: true })).rejects.toThrow(); expect(api.post).not.toHaveBeenCalled();
});
test('validates page totals, row identities, history context and exact event protocol', async () => {
  const client = await ready(); expect((await client.list()).total).toBe(1); await client.get(workflowId);
  expect((await client.history(workflowId)).events).toHaveLength(1);
  events.events[0].deliveryStatus = 'delivered'; await expect(client.history(workflowId)).rejects.toThrow();
  await client.reload(); queue.total = 2; await expect(client.list()).rejects.toThrow();
  await client.reload(); events = { ...historyFixture(), tenantId: otherId }; await expect(client.history(workflowId)).rejects.toThrow();
});
test('session error aborts a write and retains its ID even if a stale response arrives', async () => {
  const client = await ready(); const snapshot = await client.preview(userId); const pending = deferred<any>();
  (api.post as jest.Mock).mockReturnValue(pending.promise);
  const writing = client.create(snapshot, { reason, confirm: true }); const rejected = expect(writing).rejects.toThrow();
  await Promise.resolve(); await Promise.resolve();
  expect(api.post).toHaveBeenCalledTimes(1); const signal = (api.post as jest.Mock).mock.calls[0][2].signal;
  window.dispatchEvent(new CustomEvent('od:session-error')); expect(signal.aborted).toBe(true);
  pending.resolve({ status: 201, data: record }); await rejected; expect(client.knownIdRecovery).toBe(workflowId);
});
test('external abort rejects late read replies and cannot authorize a write', async () => {
  const client = await ready(); const pending = deferred<any>(); const controller = new AbortController();
  (api.get as jest.Mock).mockImplementation(url => url === jobs + '/' + workflowId ? pending.promise : getResponse(url));
  const reading = client.get(workflowId, controller.signal); const rejected = expect(reading).rejects.toThrow(); controller.abort();
  pending.resolve({ status: 200, data: record, headers: { etag: offboardingEtag(record.workflow) } }); await rejected;
  await expect(client.continue(record, { reason, confirm: true })).rejects.toThrow(); expect(api.post).not.toHaveBeenCalled();
});
test('serializes concurrent writes without cancelling the first confirmed write', async () => {
  const client = await ready(); const snapshot = await client.get(workflowId); const pending = deferred<any>();
  (api.post as jest.Mock).mockReturnValue(pending.promise);
  const first = client.continue(snapshot, { reason, confirm: true });
  await expect(client.continue(snapshot, { reason, confirm: true })).rejects.toThrow();
  pending.resolve({ status: 200, data: completedFixture() }); await first; expect(api.post).toHaveBeenCalledTimes(1);
});
test('does not send an intent if durable browser UUID retention is unavailable', async () => {
  const client = await ready(); const snapshot = await client.preview(userId);
  jest.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new Error('storage unavailable'); });
  await expect(client.create(snapshot, { reason, confirm: true })).rejects.toThrow(); expect(api.post).not.toHaveBeenCalled(); expect(client.knownIdRecovery).toBeNull();
});
test('a durable checkpoint before capture and the final release before verification remain resumable journal states', async () => {
  record = jobFixture({ totalLicenses: null, completedLicenses: 0, nextAssignments: [] });
  events = historyFixture(record); const client = await ready(); const beforeCapture = await client.get(workflowId);
  expect((await client.history(workflowId)).events[0].totalLicenses).toBeNull();
  (api.post as jest.Mock).mockResolvedValue({ status: 200, data: jobFixture({ revision: '3' }) });
  await client.continue(beforeCapture, { reason, confirm: true });
  expect((api.post as jest.Mock).mock.calls[0][1].assignments).toEqual([]);
  record = jobFixture({ revision: '4', completedLicenses: 26, nextAssignments: [] });
  const beforeVerify = await client.get(workflowId); expect(beforeVerify.workflow.phase).toBe('licenses');
  (api.post as jest.Mock).mockResolvedValue({ status: 200, data: completedFixture({ revision: '5' }) });
  await client.continue(beforeVerify, { reason, confirm: true }); expect(api.post).toHaveBeenCalledTimes(2);
});
test.each(['checkpoint', 'captured-assignment', 'requested-revision'])('rejects changed immutable %s on later GET even with unchanged summary', async field => {
  const client = await ready(); await client.get(workflowId);
  if (field === 'checkpoint') record.workflow.checkpoint.actorUserId = otherId;
  if (field === 'captured-assignment') record.workflow.nextAssignments[0].assignmentId = otherId;
  if (field === 'requested-revision') { record.workflow.requestedRevision = '9007199254740992'; record.workflow.checkpoint.beforeRevision = '9007199254740992'; }
  await expect(client.get(workflowId)).rejects.toThrow(); expect(api.post).not.toHaveBeenCalled();
});
test('fresh paused review versions may change without changing the captured grant or journal revision', async () => {
  record = jobFixture({ phase: 'paused', failure: { code: 412, step: 'licenses' }, reviewAssignments: [itemFixture()] });
  const client = await ready(); const first = await client.get(workflowId);
  record.workflow.reviewAssignments[0].poolRevision = '9007199254741000';
  const second = await client.get(workflowId);
  expect(second.workflow.reviewAssignments[0].poolRevision).toBe('9007199254741000');
  await expect(client.continue(first, { reason, confirm: true })).rejects.toThrow(); expect(api.post).not.toHaveBeenCalled();
});
test.each(['0', '-1', '01', '1.0', ' 1', '9223372036854775808'])('rejects non-PG preview revision %s', async value => {
  preview = previewFixture({ userRevision: value }); const client = await ready(); await expect(client.preview(userId)).rejects.toThrow();
});
test('reason normalization is bounded by Unicode characters without extra request fields', async () => {
  expect(offboardingReason(' ' + reason + ' ')).toBe(reason); expect(offboardingReason('😀'.repeat(500))).toHaveLength(1000);
  const client = await ready(); const snapshot = await client.preview(userId);
  await expect(client.create(snapshot, { reason, confirm: true, token: 'forbidden' } as any)).rejects.toThrow(); expect(api.post).not.toHaveBeenCalled();
});
