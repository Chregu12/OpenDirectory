import { api } from '@/lib/api';
import { CompanyMicrosoftClient } from '@/lib/companyMicrosoft';
import { microsoftId as id, microsoftContext, microsoftEnvelope, microsoftState, microsoftMappings, microsoftProducts, microsoftPool, microsoftPerson, microsoftPreview, microsoftSyncReceipt, microsoftRecoveryPreview, microsoftRecoveryReceipt, microsoftReviewPreview, microsoftReviewReceipt, microsoftResponse as ok } from '../fixtures/companyMicrosoft';
jest.mock('@/lib/api', () => ({ api: { get: jest.fn(), post: jest.fn() } }));
const clients: CompanyMicrosoftClient[] = []; const base = '/api/licenses/company/provider/microsoft';
let state: ReturnType<typeof microsoftState>; let mappings: ReturnType<typeof microsoftMappings>; let products: ReturnType<typeof microsoftProducts>;
beforeEach(() => {
  jest.resetAllMocks(); state = microsoftState(); mappings = microsoftMappings(); products = microsoftProducts(); let sequence = 100;
  Object.defineProperty(crypto, 'randomUUID', { configurable: true, value: jest.fn(() => id(sequence++)) });
  (api.get as jest.Mock).mockImplementation(async (url: string) => {
    if (url.endsWith('/state')) return ok(state);
    if (url.endsWith('/mappings')) return ok(mappings);
    if (url.endsWith('/products')) return ok(products);
    throw new Error('Unexpected Microsoft read');
  });
});
afterEach(() => clients.splice(0).forEach(current => current.dispose()));
function client() { const current = new CompanyMicrosoftClient(microsoftContext); clients.push(current); return current; }
test('pool binding captures the reviewed SKU and exact connection version without rounding bigint', async () => {
  const current = client(), view = await current.state(), inventory = await current.products();
  const intent = current.bindPool(view, inventory, id(8), id(9), 'Reviewed product binding');
  (api.post as jest.Mock).mockResolvedValue(ok({ ...microsoftEnvelope, pool: { ...microsoftPool(), id: intent.operationId }, historical: false }, 201, { etag: `"company-microsoft-pool-${intent.operationId}-1"` }));
  expect(await current.write(intent)).toEqual({ operationId: intent.operationId, action: 'bind_pool', historical: false });
  expect(api.post).toHaveBeenCalledWith(base + '/pools/' + id(8) + '/bind', { reason: 'Reviewed product binding', confirm: true, skuId: id(9), exclusiveDirectManagement: true }, expect.objectContaining({ headers: { 'Idempotency-Key': intent.operationId, 'If-Match': `"company-microsoft-connection-${id(3)}-9007199254740993"` } }));
  expect(Object.isFrozen(intent.body)).toBe(true);
});
test('new connection approval includes exactly the displayed public Microsoft configuration', async () => {
  state.state = 'configured'; state.connection = null; const current = client(), view = await current.state();
  const intent = current.connect(view, 'Reviewed Microsoft directory');
  expect(intent.body).toEqual({ reason: 'Reviewed Microsoft directory', confirm: true, microsoftTenantId: id(4), readClientId: id(5), writeClientId: id(6) });
  expect(intent.path).toBe('/connections'); expect(intent.etag).toBeNull();
});
test('retirement requires an actually captured mapping and keeps its exact revision', async () => {
  const current = client(), view = await current.state(), rows = await current.mappings(id(8));
  const intent = current.retire(view, 'user', rows.users[0], 'Reviewed mapping retirement');
  expect(intent.etag).toBe(`"company-microsoft-user-${id(10)}-1"`); expect(intent.expectedRevision).toBe('2');
  expect(() => current.retire(view, 'user', { ...rows.users[0] }, 'Reviewed mapping retirement')).toThrow();
});
test('an existing connection cannot be renewed onto a different Microsoft directory', async () => {
  state.state = 'review_required'; state.microsoftTenantId = id(99); const current = client(); const view = await current.state();
  expect(() => current.connect(view, 'Reviewed application rotation', true)).toThrow(); expect(api.post).not.toHaveBeenCalled();
});
test.each(['company', 'actor', 'connection', 'duplicate', 'page'])('unbound %s mappings invalidate all previously captured intents', async kind => {
  const current = client(), view = await current.state(); const intent = current.bindUser(view, id(11), id(12), 'Reviewed account mapping');
  if (kind === 'company') mappings.tenantId = id(99);
  if (kind === 'actor') mappings.actorUserId = id(99);
  if (kind === 'connection') mappings.users[0].connectionId = id(99);
  if (kind === 'duplicate') mappings.users.push(microsoftPerson());
  if (kind === 'page') mappings.page = 2;
  await expect(current.mappings(id(8))).rejects.toThrow(); expect(current.canRetry(intent)).toBe(false); expect(api.post).not.toHaveBeenCalled();
});
test('vendor products from another Microsoft directory cannot become a pool binding', async () => {
  const current = client(); await current.state(); products.microsoftTenantId = id(99); await expect(current.products()).rejects.toThrow(); expect(api.post).not.toHaveBeenCalled();
});
test('an uncertain metadata response never retries automatically and an explicit retry keeps the original key/body', async () => {
  const current = client(), view = await current.state(); const intent = current.bindUser(view, id(11), id(12), 'Reviewed account mapping');
  (api.post as jest.Mock).mockRejectedValueOnce(new Error('lost response'));
  await expect(current.write(intent)).rejects.toThrow(); expect(api.post).toHaveBeenCalledTimes(1); expect(current.canRetry(intent)).toBe(true);
  (api.post as jest.Mock).mockResolvedValueOnce(ok({ ...microsoftEnvelope, user: { ...microsoftPerson(), id: intent.operationId }, historical: true }, 200, { etag: `"company-microsoft-user-${intent.operationId}-1"` }));
  expect((await current.write(intent)).historical).toBe(true);
  const calls = (api.post as jest.Mock).mock.calls; expect(calls[1][1]).toBe(calls[0][1]); expect(calls[1][2].headers).toEqual(calls[0][2].headers);
});
test('a session change while a read is pending prevents late results and any write', async () => {
  const current = client(), view = await current.state(); const intent = current.bindUser(view, id(11), id(12), 'Reviewed account mapping'); let resolve!: (value: unknown) => void;
  (api.get as jest.Mock).mockImplementationOnce(() => new Promise(done => { resolve = done; }));
  const pending = current.products(); window.dispatchEvent(new Event('od:session-error')); resolve(ok(products)); await expect(pending).rejects.toThrow();
  await expect(current.write(intent)).rejects.toThrow(); expect(api.post).not.toHaveBeenCalled();
});
test('cloud preview is a read-only POST for exact bound targets and preserves its server fingerprint', async () => {
  const current = client(); await current.state(); (api.post as jest.Mock).mockResolvedValue(ok(microsoftPreview()));
  const value = await current.preview(id(8), id(11)); expect(value.local.desired).toBe(true); expect(value.action).toBe('assign'); expect(value.target).toBeNull(); expect(Object.isFrozen(value.local.raw.origins)).toBe(true);
  expect(api.post).toHaveBeenCalledTimes(1); expect(api.post).toHaveBeenCalledWith(base + '/pools/' + id(8) + '/users/' + id(11) + '/preview', {}, { signal: expect.any(AbortSignal) });
});
test.each(['user', 'pool', 'company', 'connection', 'plan', 'generation', 'observation'])('a mismatched %s cloud preview never becomes usable', async kind => {
  const current = client(); await current.state(); const value = microsoftPreview();
  if (kind === 'user') value.user.userId = id(99); if (kind === 'pool') value.local.raw.poolId = id(99); if (kind === 'company') value.pool.tenantId = id(99);
  if (kind === 'connection') value.connection.revision = '1'; if (kind === 'plan') value.action = 'remove'; if (kind === 'generation') value.local.raw.assignment.eligibilityRevision = '2'; if (kind === 'observation') value.remote.direct = true;
  (api.post as jest.Mock).mockResolvedValue(ok(value)); await expect(current.preview(id(8), id(11))).rejects.toThrow(); expect(api.post).toHaveBeenCalledTimes(1);
});
test('sync keeps the exact reviewed action and request key and treats acknowledgement only as pending', async () => {
  const current = client(); await current.state(); (api.post as jest.Mock).mockResolvedValueOnce(ok(microsoftPreview()));
  const value = await current.preview(id(8), id(11)); const intent = current.captureSync(value, 'Reviewed original license action');
  (api.post as jest.Mock).mockResolvedValueOnce(ok(microsoftSyncReceipt(intent.operationId))); const result = await current.sync(intent);
  expect(result.result.status).toBe('verifying'); expect(result.result.pendingOperationId).toBe(intent.operationId);
  expect(api.post).toHaveBeenLastCalledWith(base + '/pools/' + id(8) + '/users/' + id(11) + '/sync', { fingerprint: value.fingerprint, action: 'assign', reason: 'Reviewed original license action', confirm: true }, expect.objectContaining({ headers: { 'Idempotency-Key': intent.operationId }, timeout: 60000 }));
  expect(() => current.captureSync({ ...value }, 'Uncaptured provider action')).toThrow();
});
test.each(['company', 'user', 'action', 'revision', 'fake_confirmation'])('a mismatched %s sync receipt remains unconfirmed', async kind => {
  const current = client(); await current.state(); (api.post as jest.Mock).mockResolvedValueOnce(ok(microsoftPreview())); const value = await current.preview(id(8), id(11)); const intent = current.captureSync(value, 'Reviewed original license action'); const receipt = microsoftSyncReceipt(intent.operationId);
  if (kind === 'company') receipt.tenantId = id(99); if (kind === 'user') receipt.result.userId = id(99); if (kind === 'action') receipt.result.action = 'remove'; if (kind === 'revision') receipt.result.targetRevision = '3'; if (kind === 'fake_confirmation') receipt.result.status = 'confirmed';
  (api.post as jest.Mock).mockResolvedValueOnce(ok(receipt)); await expect(current.sync(intent)).rejects.toThrow();
});
test('unknown sync result has no automatic retry and an explicit continuation reuses its exact frozen body', async () => {
  const current = client(); await current.state(); (api.post as jest.Mock).mockResolvedValueOnce(ok(microsoftPreview())); const value = await current.preview(id(8), id(11)); const intent = current.captureSync(value, 'Reviewed original license action');
  (api.post as jest.Mock).mockRejectedValueOnce(new Error('lost reply')); await expect(current.sync(intent)).rejects.toThrow(); expect(current.canRetry(intent)).toBe(true); expect(api.post).toHaveBeenCalledTimes(2);
  const receipt = microsoftSyncReceipt(intent.operationId); (api.post as jest.Mock).mockResolvedValueOnce(ok({ ...receipt, historical: true })); expect((await current.sync(intent)).historical).toBe(true);
  const calls = (api.post as jest.Mock).mock.calls; expect(calls[2][1]).toBe(calls[1][1]); expect(calls[2][2].headers).toEqual(calls[1][2].headers);
});
test('history distinguishes original human preparation from workload delivery receipts', async () => {
  const current = client(); await current.state(); (api.get as jest.Mock).mockImplementation(async (url: string) => url.endsWith('/state') ? ok(microsoftState()) : ok({ ...microsoftEnvelope, page: 1, hasMore: false, events: [
    { id: id(80), operationId: id(100), type: 'sync_finished', actorKind: 'workload', actorUserId: null, reason: 'Original human provider action', createdAt: '2026-11-16T00:00:00.000Z', resource: null },
  ] })); const value = await current.history(); expect(value.events[0].actorKind).toBe('workload'); expect(value.events[0].actorUserId).toBeNull();
});

test.each(['prepared', 'dispatched'] as const)('recovery binds the original %s phase and accepts only its separate non-dispatch receipt', async phase => {
  const current = client(); await current.state(); (api.post as jest.Mock).mockResolvedValueOnce(ok(microsoftRecoveryPreview(phase)));
  const view = await current.recoveryPreview(id(8), id(11)); const intent = current.captureRecovery(view, 'Reviewed crash recovery');
  expect(intent.body.interruptedOperationId).toBe(id(40)); expect(intent.body.interruptedPhase).toBe(phase); expect(Object.isFrozen(intent.body)).toBe(true);
  (api.post as jest.Mock).mockResolvedValueOnce(ok(microsoftRecoveryReceipt(intent.operationId, phase))); expect((await current.recover(intent)).result.action).toBe('recover');
  expect(api.post).toHaveBeenLastCalledWith(base + '/pools/' + id(8) + '/users/' + id(11) + '/recover', intent.body, expect.objectContaining({ headers: { 'Idempotency-Key': intent.operationId } }));
});
test.each(['company', 'original_operation', 'phase', 'revision', 'ownership', 'acknowledgement'])('a recovery receipt with a changed %s cannot become success', async kind => {
  const current = client(); await current.state(); (api.post as jest.Mock).mockResolvedValueOnce(ok(microsoftRecoveryPreview()));
  const intent = current.captureRecovery(await current.recoveryPreview(id(8), id(11)), 'Reviewed crash recovery'); const result = microsoftRecoveryReceipt(intent.operationId);
  if (kind === 'company') result.tenantId = id(99); if (kind === 'original_operation') result.result.interruptedOperationId = id(99);
  if (kind === 'phase') result.result.interruptedPhase = 'prepared'; if (kind === 'revision') result.result.targetRevision = '3'; if (kind === 'ownership') result.result.owned = true;
  if (kind === 'acknowledgement') { result.result.kind = 'acknowledged'; result.result.status = 'confirmed'; }
  (api.post as jest.Mock).mockResolvedValueOnce(ok(result)); await expect(current.recover(intent)).rejects.toThrow();
});
test('lost recovery replies do not retry automatically and explicit continuation retains its exact original key', async () => {
  const current = client(); await current.state(); (api.post as jest.Mock).mockResolvedValueOnce(ok(microsoftRecoveryPreview()));
  const intent = current.captureRecovery(await current.recoveryPreview(id(8), id(11)), 'Reviewed crash recovery');
  (api.post as jest.Mock).mockRejectedValueOnce(new Error('lost recovery reply')); await expect(current.recover(intent)).rejects.toThrow(); expect(api.post).toHaveBeenCalledTimes(2);
  (api.post as jest.Mock).mockResolvedValueOnce(ok({ ...microsoftRecoveryReceipt(intent.operationId), historical: true })); expect((await current.recover(intent)).historical).toBe(true);
  const calls = (api.post as jest.Mock).mock.calls; expect(calls[2][1]).toBe(calls[1][1]); expect(calls[2][2].headers).toEqual(calls[1][2].headers);
});
test('an empty interrupted-operation check cannot produce a recovery intent', async () => {
  const current = client(); await current.state(); (api.post as jest.Mock).mockResolvedValueOnce(ok({ ...microsoftRecoveryPreview(), attempt: null, target: null, fingerprint: null }));
  const view = await current.recoveryPreview(id(8), id(11)); expect(() => current.captureRecovery(view, 'Reviewed crash recovery')).toThrow(); expect(api.post).toHaveBeenCalledTimes(1);
});

test.each(['adopt', 'release'] as const)('unknown review captures the original uncertain attempt and explicit %s decision', async decision => {
  const current = client(); await current.state(); (api.post as jest.Mock).mockResolvedValueOnce(ok(microsoftReviewPreview(decision)));
  const view = await current.reviewPreview(id(8), id(11)); const intent = current.captureReview(view, decision, 'Reviewed unknown license effect');
  expect(intent.body.uncertainOperationId).toBe(id(40)); expect(Object.isFrozen(intent.body)).toBe(true);
  (api.post as jest.Mock).mockResolvedValueOnce(ok(microsoftReviewReceipt(intent.operationId, decision))); expect((await current.review(intent)).result.decision).toBe(decision);
  expect(api.post).toHaveBeenLastCalledWith(base + '/pools/' + id(8) + '/users/' + id(11) + '/review', intent.body, expect.objectContaining({ headers: { 'Idempotency-Key': intent.operationId } }));
});
test.each(['company', 'original_operation', 'decision', 'revision', 'ownership', 'unresolved_pointer'])('an unknown-review receipt with a changed %s remains unconfirmed', async kind => {
  const current = client(); await current.state(); (api.post as jest.Mock).mockResolvedValueOnce(ok(microsoftReviewPreview())); const intent = current.captureReview(await current.reviewPreview(id(8), id(11)), 'adopt', 'Reviewed unknown license effect'); const receipt = microsoftReviewReceipt(intent.operationId);
  if (kind === 'company') receipt.tenantId = id(99); if (kind === 'original_operation') receipt.result.uncertainOperationId = id(99); if (kind === 'decision') receipt.result.decision = 'release';
  if (kind === 'revision') receipt.result.targetRevision = '4'; if (kind === 'ownership') receipt.result.owned = false; if (kind === 'unresolved_pointer') receipt.result.uncertainOperationIdAfter = id(40);
  (api.post as jest.Mock).mockResolvedValueOnce(ok(receipt)); await expect(current.review(intent)).rejects.toThrow();
});
test('cleanup adoption cannot be represented as an active positive entitlement', async () => {
  const current = client(); await current.state(); (api.post as jest.Mock).mockResolvedValueOnce(ok(microsoftReviewPreview('adopt', true))); const intent = current.captureReview(await current.reviewPreview(id(8), id(11)), 'adopt', 'Reviewed controlled cleanup');
  expect(intent.cleanup).toBe(true); expect(intent.canConfirm).toBe(false); (api.post as jest.Mock).mockResolvedValueOnce(ok(microsoftReviewReceipt(intent.operationId, 'adopt', true))); expect((await current.review(intent)).result.status).toBe('conflict');
  (api.post as jest.Mock).mockResolvedValueOnce(ok(microsoftReviewReceipt(intent.operationId))); await expect(current.review(intent)).rejects.toThrow();
});
test('review waits for the original dispatch window and rejects adoption of a pre-existing license', async () => {
  const current = client(); await current.state(); const early = microsoftReviewPreview(); early.attempt.finishedAt = new Date().toISOString(); early.attempt.notBefore = new Date(Date.now() + 30000).toISOString();
  (api.post as jest.Mock).mockResolvedValueOnce(ok(early)); const view = await current.reviewPreview(id(8), id(11)); expect(() => current.captureReview(view, 'adopt', 'Reviewed unknown license effect')).toThrow();
  const external = microsoftReviewPreview(); external.attempt.before.present = true; (api.post as jest.Mock).mockResolvedValueOnce(ok(external)); await expect(current.reviewPreview(id(8), id(11))).rejects.toThrow();
});
test('lost review replies have no automatic retry and explicit continuation keeps the original frozen request', async () => {
  const current = client(); await current.state(); (api.post as jest.Mock).mockResolvedValueOnce(ok(microsoftReviewPreview())); const intent = current.captureReview(await current.reviewPreview(id(8), id(11)), 'adopt', 'Reviewed unknown license effect');
  (api.post as jest.Mock).mockRejectedValueOnce(new Error('lost review reply')); await expect(current.review(intent)).rejects.toThrow(); expect(api.post).toHaveBeenCalledTimes(2);
  (api.post as jest.Mock).mockResolvedValueOnce(ok({ ...microsoftReviewReceipt(intent.operationId), historical: true })); expect((await current.review(intent)).historical).toBe(true);
  const calls = (api.post as jest.Mock).mock.calls; expect(calls[2][1]).toBe(calls[1][1]); expect(calls[2][2].headers).toEqual(calls[1][2].headers);
});
