import { CompanyOffboardingAccessClient, OffboardingAccessBinding, offboardingAccessReason } from '@/lib/companyOffboardingAccess';

const actorUserId = '11111111-1111-4111-8111-111111111111';
const tenantId = '22222222-2222-4222-8222-222222222222';
const userId = '33333333-3333-4333-8333-333333333333';
const workflowId = '44444444-4444-4444-8444-444444444444';
const otherId = '99999999-9999-4999-8999-999999999999';
const identifier = (index: number) => `55555555-5555-4555-8555-${String(index).padStart(12, '0')}`;
const version = 'a'.repeat(64);
const reason = 'Geprüfter Austritt des Mitarbeiters';
const createdAt = '2026-10-19T10:00:00.000Z';
const target = { enabled: false, eligibilityRevision: '9007199254740993' };
const binding = { schemaVersion: 1, actorUserId, tenantId, workflowId, userId };
const props: OffboardingAccessBinding = { expectedActorUserId: actorUserId, userId, workflowId };
const base = '/api/users/' + userId + '/company-offboarding-access';
const item = (index = 1, changes = {}) => ({ id: identifier(index), role: 'directory-reader', version, createdAt, expiresAt: null, canRevoke: true, blockedReason: null, ...changes });
const capabilitiesFixture = (changes = {}): any => ({ ...binding, companyOffboardingAccessProtocol: 1, target, permissions: ['identities.roles.read', 'identities.roles.manage', 'pim.eligibilities.read', 'pim.eligibilities.manage'], supportedKinds: ['role', 'eligibility'], ...changes });
const previewFixture = (changes = {}): any => ({ ...binding, companyOffboardingAccessProtocol: 1, target, kind: 'role', canRevoke: true, items: [item()], total: 1, page: 1, limit: 25, ...changes });
const historyFixture = (changes = {}): any => ({ ...binding, target, kind: 'role', receipts: [], total: 0, page: 1, limit: 25, ...changes });
const receipt = (changes = {}): any => ({ id: identifier(50), resourceId: identifier(1), role: 'directory-reader', version, kind: 'role', checkpointId: identifier(60), actorUserId, correlationId: identifier(70), reason, createdAt, deliveryStatus: 'pending', ...changes });
const result = (index = 1, changes = {}) => ({ id: identifier(index), status: 'revoked', code: 200, checkpointId: identifier(index + 60), ...changes });
const outcomeFixture = (changes = {}): any => ({ ...binding, kind: 'role', correlationId: identifier(70), results: [result()], ...changes });
const mockGet = jest.fn(); const mockPost = jest.fn();
jest.mock('@/lib/api', () => ({ api: { get: (...args: unknown[]) => mockGet(...args), post: (...args: unknown[]) => mockPost(...args) } }));
let capabilities: any; let preview: any; let history: any;
const clients: CompanyOffboardingAccessClient[] = [];
const client = (values = props) => { const current = new CompanyOffboardingAccessClient(values); clients.push(current); return current; };
async function ready(current = client(), kind: 'role' | 'eligibility' = 'role') {
  await current.capabilities(); const snapshot = await current.preview(kind); await current.history(kind); return { current, snapshot };
}
async function intentReady() {
  const { current, snapshot } = await ready(); const intent = current.capture(snapshot, snapshot.items.map(row => row.id), { reason, confirm: true }); return { current, snapshot, intent };
}
function deferred() { let resolve: (value: any) => void; const promise = new Promise<any>(complete => { resolve = complete; }); return { promise, resolve: (value: any) => resolve(value) }; }
beforeEach(() => {
  jest.resetAllMocks(); capabilities = capabilitiesFixture(); preview = previewFixture(); history = historyFixture();
  mockGet.mockImplementation(async (url: string) => {
    if (url === base + '/capabilities') return { status: 200, data: capabilities };
    if (url === base) return { status: 200, data: preview };
    if (url === base + '/history') return { status: 200, data: history };
    throw new Error('Unexpected endpoint ' + url);
  });
  mockPost.mockResolvedValue({ status: 200, data: outcomeFixture() });
});
afterEach(() => clients.splice(0).forEach(current => current.dispose()));

test('constructs without requests and uses only exact independent endpoints and string pagination', async () => {
  const current = client(); expect(mockGet).not.toHaveBeenCalled(); const { snapshot } = await ready(current);
  expect(mockGet.mock.calls.map(([url]) => url)).toEqual([base + '/capabilities', base, base + '/history']);
  expect(mockGet).toHaveBeenNthCalledWith(1, base + '/capabilities', { params: { workflowId }, signal: expect.any(AbortSignal) });
  expect(mockGet).toHaveBeenNthCalledWith(2, base, { params: { workflowId, kind: 'role', page: '1', limit: '25' }, signal: expect.any(AbortSignal) });
  expect(mockGet).toHaveBeenNthCalledWith(3, base + '/history', { params: { workflowId, kind: 'role', page: '1', limit: '25' }, signal: expect.any(AbortSignal) });
  expect(Object.isFrozen(snapshot.items[0])).toBe(true); expect(mockPost).not.toHaveBeenCalled();
});
test('captures an exact subset in displayed order, trims reason and sends the opaque negative epoch and SQL hash', async () => {
  preview = previewFixture({ items: [item(1), item(2)], total: 2 }); const { current, snapshot } = await ready();
  const intent = current.capture(snapshot, [identifier(2)], { reason: '  ' + reason + '  ', confirm: true });
  mockPost.mockResolvedValue({ status: 200, data: outcomeFixture({ results: [result(2)] }) });
  await current.revoke(intent);
  expect(mockPost).toHaveBeenCalledWith(base, { workflowId, eligibilityRevision: target.eligibilityRevision, kind: 'role', reason, confirm: true, items: [{ id: identifier(2), version }] }, { signal: expect.any(AbortSignal) });
  expect(mockGet).toHaveBeenCalledTimes(3); await expect(current.revoke(intent)).rejects.toThrow(); expect(mockPost).toHaveBeenCalledTimes(1);
});
test('pins authoritative tenant and negative epoch on first capabilities even when no parent props were known', async () => {
  const current = client(); await current.capabilities(); capabilities = capabilitiesFixture({ tenantId: otherId });
  await expect(current.capabilities()).rejects.toThrow(); capabilities = capabilitiesFixture({ target: { ...target, eligibilityRevision: '9007199254740994' } });
  await expect(current.capabilities()).rejects.toThrow(); expect(mockPost).not.toHaveBeenCalled();
});
test('rejects a capabilities parent tenant or negative epoch different from supplied parent props', async () => {
  await expect(client({ ...props, tenantId: otherId }).capabilities()).rejects.toThrow();
  await expect(client({ ...props, eligibilityRevision: '7' }).capabilities()).rejects.toThrow();
});
test('copies and freezes constructor identity and parent inputs', async () => {
  const values = { ...props, tenantId, eligibilityRevision: target.eligibilityRevision }; const current = client(values);
  values.workflowId = otherId; values.eligibilityRevision = '7'; const { snapshot } = await ready(current);
  const intent = current.capture(snapshot, [identifier(1)], { reason, confirm: true }); await current.revoke(intent);
  expect(mockPost.mock.calls[0][1]).toEqual(expect.objectContaining({ workflowId, eligibilityRevision: target.eligibilityRevision }));
});
test.each([
  ['missing schema', { schemaVersion: undefined }], ['old protocol', { companyOffboardingAccessProtocol: 0 }], ['extra field', { roles: ['admin'] }],
  ['actor', { actorUserId: otherId }], ['user', { userId: otherId }], ['workflow', { workflowId: otherId }],
  ['self', { actorUserId: userId }], ['uppercase tenant', { tenantId: 'ABCDEF12-2222-4222-8222-222222222222' }],
  ['positive target', { target: { ...target, enabled: true } }], ['numeric epoch', { target: { ...target, eligibilityRevision: 1 } }],
  ['leading-zero epoch', { target: { ...target, eligibilityRevision: '01' } }], ['overflow epoch', { target: { ...target, eligibilityRevision: '9223372036854775808' } }],
  ['target field', { target: { ...target, authorizationRevision: '8' } }], ['owner alias', { permissions: ['company.apps.assign'] }],
  ['duplicate permission', { permissions: ['identities.roles.read', 'identities.roles.read'] }],
  ['duplicate kind', { supportedKinds: ['role', 'role'] }], ['missing kind', { supportedKinds: ['role'] }],
  ['unsupported kind', { supportedKinds: ['group'] }], ['no read duty', { permissions: ['identities.roles.manage'], supportedKinds: ['role'] }],
  ['no supported reads', { permissions: [], supportedKinds: [] }],
])('fails closed for capabilities %s with no alternate endpoints', async (_label, changes) => {
  capabilities = capabilitiesFixture(changes); await expect(client().capabilities()).rejects.toThrow(); expect(mockGet).toHaveBeenCalledTimes(1); expect(mockPost).not.toHaveBeenCalled();
});
test('allows PIM-only read and management without roles, users.read or company.apps', async () => {
  capabilities = capabilitiesFixture({ permissions: ['pim.eligibilities.read', 'pim.eligibilities.manage'], supportedKinds: ['eligibility'] });
  preview = previewFixture({ kind: 'eligibility' }); history = historyFixture({ kind: 'eligibility' });
  const { current, snapshot } = await ready(client(), 'eligibility'); const intent = current.capture(snapshot, [identifier(1)], { reason, confirm: true });
  mockPost.mockResolvedValue({ status: 200, data: outcomeFixture({ kind: 'eligibility' }) }); await current.revoke(intent);
  expect(mockPost.mock.calls[0][1].kind).toBe('eligibility'); expect(mockGet.mock.calls.some(([url]) => url === '/api/users')).toBe(false);
});
test('read-only actual roles reader sees real unrevoked expired data but cannot capture', async () => {
  capabilities = capabilitiesFixture({ permissions: ['identities.roles.read'], supportedKinds: ['role'] });
  preview = previewFixture({ canRevoke: false, items: [item(1, { canRevoke: false, blockedReason: 'permission_required', expiresAt: '2026-10-19T10:01:00.000Z' })] });
  const { current, snapshot } = await ready(); expect(snapshot.items).toHaveLength(1);
  expect(() => current.capture(snapshot, [identifier(1)], { reason, confirm: true })).toThrow(); expect(mockPost).not.toHaveBeenCalled();
});
test.each([
  ['schema', { schemaVersion: 2 }], ['protocol', { companyOffboardingAccessProtocol: undefined }], ['extra', { success: true }],
  ['actor', { actorUserId: otherId }], ['tenant', { tenantId: otherId }], ['parent', { workflowId: otherId }], ['user', { userId: otherId }],
  ['target', { target: { ...target, eligibilityRevision: '7' } }], ['kind', { kind: 'eligibility' }], ['manage duty', { canRevoke: false }],
  ['unsafe total', { total: Number.MAX_SAFE_INTEGER + 1 }], ['inexact count', { total: 2 }], ['wrong page', { page: 2 }], ['wrong limit', { limit: 24 }],
  ['duplicate IDs', { items: [item(), item()], total: 2 }], ['unknown role', { items: [item(1, { role: 'company-owner' })] }],
  ['role alias', { items: [item(1, { role: 'Administrator' })] }], ['unknown field', { items: [item(1, { status: 'active' })] }],
  ['invented bigint version', { items: [item(1, { version: '9007199254740993' })] }], ['uppercase hash', { items: [item(1, { version: 'A'.repeat(64) })] }],
  ['bad hash', { items: [item(1, { version: 'g'.repeat(64) })] }], ['date', { items: [item(1, { createdAt: 'tomorrow' })] }],
  ['expiry before creation', { items: [item(1, { expiresAt: '2026-10-18T10:00:00.000Z' })] }],
  ['nonchronological rows', { items: [item(1, { createdAt: '2026-10-20T10:00:00.000Z' }), item(2)], total: 2 }],
  ['contradictory block', { items: [item(1, { blockedReason: 'protected_role' })] }],
  ['unexplained denial', { items: [item(1, { canRevoke: false })] }],
  ['nonprotected blocked', { items: [item(1, { canRevoke: false, blockedReason: 'protected_role' })] }],
  ['26 rows', { items: Array.from({ length: 26 }, (_, index) => item(index)), total: 26 }],
])('rejects preview %s before any write', async (_label, changes) => {
  preview = previewFixture(changes); const current = client(); await current.capabilities(); await expect(current.preview('role')).rejects.toThrow(); expect(mockPost).not.toHaveBeenCalled();
});
test.each([0, -1, 1.2, NaN, Infinity, 1000001, Number.MAX_SAFE_INTEGER])('rejects page %s before preview/history GET', async page => {
  const current = client(); await current.capabilities(); await expect(current.preview('role', page)).rejects.toThrow();
  await current.capabilities(); await expect(current.history('role', page)).rejects.toThrow(); expect(mockGet.mock.calls.every(([url]) => url.endsWith('/capabilities'))).toBe(true);
});
test('accepts exact 25-row pages, max page and empty pages without claiming full revocation', async () => {
  preview = previewFixture({ items: Array.from({ length: 25 }, (_, index) => item(index + 1)), total: 26 }); const current = client();
  await current.capabilities(); expect((await current.preview('role')).items).toHaveLength(25);
  preview = previewFixture({ items: [item(26)], total: 26, page: 2 }); expect((await current.preview('role', 2)).items[0].id).toBe(identifier(26));
  preview = previewFixture({ items: [], total: 26, page: 1000000 }); const empty = await current.preview('role', 1000000); await current.history('role');
  expect(() => current.capture(empty, [], { reason, confirm: true })).toThrow(); expect(mockPost).not.toHaveBeenCalled();
});
test('protected rows remain visible and cannot be selected while ordinary rows can', async () => {
  preview = previewFixture({ items: [item(1, { role: 'admin', canRevoke: false, blockedReason: 'protected_role' }), item(2)], total: 2 });
  const { current, snapshot } = await ready(); expect(snapshot.items[0].role).toBe('admin');
  expect(() => current.capture(snapshot, [identifier(1)], { reason, confirm: true })).toThrow();
  expect(current.capture(snapshot, [identifier(2)], { reason, confirm: true }).items[0].id).toBe(identifier(2));
});
test('requires original preview and fresh same-kind history, no forged snapshot or substituted hash', async () => {
  const current = client(); await current.capabilities(); const snapshot = await current.preview('role');
  expect(() => current.capture(snapshot, [identifier(1)], { reason, confirm: true })).toThrow(); await current.history('role');
  expect(() => current.capture({ ...snapshot }, [identifier(1)], { reason, confirm: true })).toThrow();
  expect(() => current.capture({ ...snapshot, items: [item(1, { version: 'b'.repeat(64) })] }, [identifier(1)], { reason, confirm: true })).toThrow();
  await current.history('eligibility').catch(() => undefined); expect(() => current.capture(snapshot, [identifier(1)], { reason, confirm: true })).toThrow();
});
test('rejects duplicate, reordered, foreign and over-limit selections', async () => {
  preview = previewFixture({ items: [item(1), item(2)], total: 2 }); const { current, snapshot } = await ready();
  for (const ids of [[identifier(1), identifier(1)], [identifier(2), identifier(1)], [otherId], Array.from({ length: 26 }, (_, index) => identifier(index))]) {
    expect(() => current.capture(snapshot, ids, { reason, confirm: true })).toThrow();
  }
  expect(mockPost).not.toHaveBeenCalled();
});
test.each(['kurz', 'x'.repeat(501), '\n' + reason, reason + '\u007f', reason + '\u0085'])('rejects reason %# without POST', async value => {
  const { current, snapshot } = await ready(); expect(() => current.capture(snapshot, [identifier(1)], { reason: value, confirm: true })).toThrow(); expect(mockPost).not.toHaveBeenCalled();
});
test('counts Unicode reason characters and requires exact confirmed input', async () => {
  expect(offboardingAccessReason('😀'.repeat(500))).toBe('😀'.repeat(500)); const { current, snapshot } = await ready();
  expect(() => current.capture(snapshot, [identifier(1)], { reason, confirm: false } as any)).toThrow();
  expect(() => current.capture(snapshot, [identifier(1)], { reason, confirm: true, admin: true } as any)).toThrow();
});
test.each([
  ['target', { target: { ...target, enabled: true } }], ['kind', { kind: 'eligibility' }], ['tenant', { tenantId: otherId }],
  ['extra field', { verified: true }], ['wrong count', { total: 2 }],
  ['extra receipt field', { receipts: [receipt({ success: true })], total: 1 }], ['wrong receipt kind', { receipts: [receipt({ kind: 'eligibility' })], total: 1 }],
  ['invented checkpoint', { receipts: [receipt({ checkpointId: null })], total: 1 }], ['sent delivery', { receipts: [receipt({ deliveryStatus: 'sent' })], total: 1 }],
  ['self actor', { receipts: [receipt({ actorUserId: userId })], total: 1 }], ['unknown role', { receipts: [receipt({ role: 'owner' })], total: 1 }],
  ['bad hash', { receipts: [receipt({ version: '1' })], total: 1 }], ['reason whitespace', { receipts: [receipt({ reason: '  ' + reason })], total: 1 }],
  ['duplicate resource', { receipts: [receipt(), receipt({ id: identifier(51), checkpointId: identifier(61) })], total: 2 }],
  ['duplicate checkpoint', { receipts: [receipt(), receipt({ id: identifier(51), resourceId: identifier(2) })], total: 2 }],
  ['nonchronological receipts', { receipts: [receipt({ createdAt: '2026-10-20T10:00:00.000Z' }), receipt({ id: identifier(51), resourceId: identifier(2), checkpointId: identifier(61) })], total: 2 }],
])('rejects history %s', async (_label, changes) => {
  history = historyFixture(changes); const current = client(); await current.capabilities(); await expect(current.history('role')).rejects.toThrow(); expect(mockPost).not.toHaveBeenCalled();
});
test('rejects changed retained receipt and duplicate resource receipt across pages', async () => {
  history = historyFixture({ receipts: [receipt()], total: 1 }); const current = client(); await current.capabilities(); await current.history('role');
  history = historyFixture({ receipts: [receipt({ reason: 'Eine andere echte Begründung' })], total: 1 }); await expect(current.history('role')).rejects.toThrow();
  await current.capabilities(); history = historyFixture({ receipts: [receipt({ id: identifier(51) })], total: 1 }); await expect(current.history('role')).rejects.toThrow();
});
test('partial response must stop at the first unconfirmed item and match exact original ordering', async () => {
  preview = previewFixture({ items: [item(1), item(2), item(3)], total: 3 }); const { current, snapshot } = await ready();
  const intent = current.capture(snapshot, snapshot.items.map(row => row.id), { reason, confirm: true });
  mockPost.mockResolvedValue({ status: 207, data: outcomeFixture({ results: [result(), result(2, { status: 'unconfirmed', code: 503, checkpointId: null }), result(3, { status: 'not_attempted', code: null, checkpointId: null })] }) });
  const outcome = await current.revoke(intent); expect(outcome.results.map(row => row.status)).toEqual(['revoked', 'unconfirmed', 'not_attempted']); expect(mockGet).toHaveBeenCalledTimes(3);
});
test.each([
  ['actor', { actorUserId: otherId }], ['tenant', { tenantId: otherId }], ['workflow', { workflowId: otherId }], ['user', { userId: otherId }],
  ['kind', { kind: 'eligibility' }], ['extra field', { success: true }], ['empty results', { results: [] }], ['duplicate result', { results: [result(), result()] }],
  ['foreign result', { results: [result(2)] }], ['missing checkpoint', { results: [result(1, { checkpointId: null })] }],
  ['unknown status', { results: [result(1, { status: 'success' })] }], ['wrong success code', { results: [result(1, { code: 201 })] }],
  ['unconfirmed checkpoint', { results: [result(1, { status: 'unconfirmed', code: 503 })] }],
  ['not attempted without stop', { results: [result(1, { status: 'not_attempted', code: null, checkpointId: null })] }],
])('never accepts ambiguous outcome %s and never retries', async (_label, changes) => {
  const { current, intent } = await intentReady(); mockPost.mockResolvedValue({ status: 200, data: outcomeFixture(changes) });
  await expect(current.revoke(intent)).rejects.toThrow(); expect(mockPost).toHaveBeenCalledTimes(1); expect(mockGet).toHaveBeenCalledTimes(3);
});
test.each([201, 202, 204, 206, 503])('rejects noncontract status %s without retry', async status => {
  const { current, intent } = await intentReady(); mockPost.mockResolvedValue({ status, data: outcomeFixture() }); await expect(current.revoke(intent)).rejects.toThrow(); expect(mockPost).toHaveBeenCalledTimes(1);
});
test('rejects 207 with no uncertainty and 200 with uncertainty', async () => {
  const first = await intentReady(); mockPost.mockResolvedValue({ status: 207, data: outcomeFixture() }); await expect(first.current.revoke(first.intent)).rejects.toThrow();
  const second = await intentReady(); mockPost.mockResolvedValue({ status: 200, data: outcomeFixture({ results: [result(1, { status: 'unconfirmed', code: 503, checkpointId: null })] }) });
  await expect(second.current.revoke(second.intent)).rejects.toThrow(); expect(mockPost).toHaveBeenCalledTimes(2);
});
test('rejects later writes after first uncertainty, reordered results and duplicate checkpoints', async () => {
  preview = previewFixture({ items: [item(1), item(2)], total: 2 });
  for (const results of [[result(1, { status: 'unconfirmed', code: 503, checkpointId: null }), result(2)], [result(2), result(1)], [result(1), result(2, { checkpointId: result().checkpointId })]]) {
    const { current, snapshot } = await ready(); const intent = current.capture(snapshot, snapshot.items.map(row => row.id), { reason, confirm: true });
    mockPost.mockResolvedValue({ status: 207, data: outcomeFixture({ results }) }); await expect(current.revoke(intent)).rejects.toThrow();
  }
  expect(mockPost).toHaveBeenCalledTimes(3);
});
test('unknown response requires explicit same-intent recovery after readback and preserves newly granted rows', async () => {
  const { current, intent } = await intentReady(); mockPost.mockRejectedValueOnce(new Error('Lost ACK'));
  await expect(current.revoke(intent)).rejects.toThrow(); await expect(current.revoke(intent, true)).rejects.toThrow(); expect(mockPost).toHaveBeenCalledTimes(1);
  preview = previewFixture({ items: [item(2, { version: 'b'.repeat(64) })] }); history = historyFixture({ receipts: [receipt({ checkpointId: result().checkpointId })], total: 1 });
  await ready(current); mockPost.mockResolvedValue({ status: 200, data: outcomeFixture({ results: [result(1, { status: 'already_revoked' })] }) });
  await current.revoke(intent, true); expect(mockPost.mock.calls[1][1].items).toEqual([{ id: identifier(1), version }]);
  expect(mockGet).toHaveBeenCalledTimes(6); expect(mockPost).toHaveBeenCalledTimes(2);
  await ready(current); await expect(current.revoke(intent, true)).rejects.toThrow(); expect(mockPost).toHaveBeenCalledTimes(2);
});
test('recovery refuses mismatched original checkpoint proof', async () => {
  const { current, intent } = await intentReady(); mockPost.mockRejectedValueOnce(new Error('Lost ACK')); await expect(current.revoke(intent)).rejects.toThrow();
  history = historyFixture({ receipts: [receipt()], total: 1 }); await ready(current);
  mockPost.mockResolvedValue({ status: 200, data: outcomeFixture({ results: [result(1, { status: 'already_revoked', checkpointId: otherId })] }) });
  await expect(current.revoke(intent, true)).rejects.toThrow(); expect(mockPost).toHaveBeenCalledTimes(2);
});
test('does not allow concurrent POST, read or capability refresh during write', async () => {
  const { current, intent } = await intentReady(); const pending = deferred(); mockPost.mockReturnValue(pending.promise); const writing = current.revoke(intent);
  await expect(current.revoke(intent)).rejects.toThrow(); await expect(current.capabilities()).rejects.toThrow(); await expect(current.preview('role')).rejects.toThrow(); await expect(current.history('role')).rejects.toThrow();
  pending.resolve({ status: 200, data: outcomeFixture() }); await writing; expect(mockPost).toHaveBeenCalledTimes(1);
});
test('session invalidation aborts a pending write, discards late success and destroys recoverable intent', async () => {
  const { current, intent } = await intentReady(); const pending = deferred(); mockPost.mockReturnValue(pending.promise); const writing = current.revoke(intent);
  const signal = mockPost.mock.calls[0][2].signal; window.dispatchEvent(new Event('od:session-error')); expect(signal.aborted).toBe(true);
  pending.resolve({ status: 200, data: outcomeFixture() }); await expect(writing).rejects.toThrow(); await ready(current); await expect(current.revoke(intent, true)).rejects.toThrow(); expect(mockPost).toHaveBeenCalledTimes(1);
});
test('dispose and external cancellation discard late reads and cannot authorize writes', async () => {
  const pending = deferred(); mockGet.mockReturnValue(pending.promise); const current = client(); const reading = current.capabilities(); current.dispose();
  pending.resolve({ status: 200, data: capabilitiesFixture() }); await expect(reading).rejects.toThrow();
  const controller = new AbortController(); controller.abort(); await expect(client().capabilities(controller.signal)).rejects.toThrow(); expect(mockGet).toHaveBeenCalledTimes(1);
});
test('a newer explicit preview cancels and discards the older late response', async () => {
  const current = client(); await current.capabilities(); const pending = deferred(); mockGet.mockReturnValueOnce(pending.promise);
  const older = current.preview('role'); const signal = mockGet.mock.calls[1][1].signal; const fresh = await current.preview('role'); expect(signal.aborted).toBe(true);
  pending.resolve({ status: 200, data: previewFixture({ items: [item(2)] }) }); await expect(older).rejects.toThrow(); await current.history('role');
  expect(current.capture(fresh, [identifier(1)], { reason, confirm: true }).items[0].id).toBe(identifier(1)); expect(mockPost).not.toHaveBeenCalled();
});
test('rejects a checkpoint reused by another receipt on a later read', async () => {
  history = historyFixture({ receipts: [receipt()], total: 1 }); const current = client(); await current.capabilities(); await current.history('role');
  history = historyFixture({ receipts: [receipt({ id: identifier(51), resourceId: identifier(2) })], total: 1 }); await expect(current.history('role')).rejects.toThrow();
});
test.each([401, 403, 404, 409, 412, 428, 503])('read failure %s does not fallback, refresh or write', async status => {
  mockGet.mockRejectedValue({ response: { status } }); await expect(client().capabilities()).rejects.toEqual({ response: { status } }); expect(mockGet).toHaveBeenCalledTimes(1); expect(mockPost).not.toHaveBeenCalled();
});
