import { api } from '@/lib/api';
import { CompanyBlueprintAssignmentsClient, companyBlueprintAssignmentEtag } from '@/lib/companyBlueprintAssignments';
import { assignmentId as id, assignmentContext, assignmentBlueprintAccess, assignmentBinding, assignmentPreview, assignmentEnvelope as envelope,
  assignmentOk as ok, assignmentConfiguration, assignmentBlueprintSource, assignmentDirect } from '../fixtures/companyAssignmentsV2';

jest.mock('@/lib/api', () => ({ api: { get: jest.fn(), post: jest.fn() } }));
const base = '/api/company-blueprint-assignments'; const clients: CompanyBlueprintAssignmentsClient[] = [];
let preview: ReturnType<typeof assignmentPreview>; let binding: ReturnType<typeof assignmentBinding>; let access: ReturnType<typeof assignmentBlueprintAccess>;
let sequence: number;
beforeEach(() => {
  jest.resetAllMocks(); sequence = 100; preview = assignmentPreview(); binding = assignmentBinding(); access = assignmentBlueprintAccess();
  Object.defineProperty(crypto, 'randomUUID', { configurable: true, value: jest.fn(() => id(sequence++)) });
  (api.get as jest.Mock).mockImplementation(async (url: string) => {
    if (url.endsWith('/capabilities')) return ok(access);
    if (url.endsWith('/removal-preview')) return ok(envelope({ assignment: binding, eligibilityRevision: '9007199254740994', pools: [{ poolId: id(20), poolRevision: '9007199254740993' }] }), { etag: companyBlueprintAssignmentEtag(binding) });
    if (url === base + '/' + id(1)) return ok(envelope({ assignment: binding }), { etag: companyBlueprintAssignmentEtag(binding) });
    if (url === base) return ok(envelope({ userId: id(5), assignments: [binding], total: 1, page: 1, limit: 25 }));
    if (url.endsWith('/effective')) return ok(envelope({ userId: id(5), assignments: [binding], effectiveConfigurations: [assignmentConfiguration()], conflicts: [], hasConflicts: false,
      applications: [{ poolId: id(20), sources: [assignmentBlueprintSource(), assignmentDirect()] }] }));
    if (url === '/api/identity/access') return ok({ userId: id(90), subject: 'human', demoMode: false, permissions: [], directoryReadProtocol: 1 });
    throw new Error('Unexpected read ' + url);
  });
  (api.post as jest.Mock).mockImplementation(async (url: string, body: any, config: any) => {
    if (url.endsWith('/preview')) return ok(preview);
    const removed = url.endsWith('/remove');
    return ok(envelope({ operationId: config.headers['Idempotency-Key'], assignmentId: removed ? id(1) : body.id, action: removed ? 'removed' : 'assigned', outcome: 'applied', revision: removed ? '2' : '1', deliveryStatus: 'pending', pools: [
      { poolId: id(20), eventId: id(60), beforeRevision: '9007199254740993', afterRevision: '9007199254740994', sourceAdded: !removed, sourceRemoved: removed,
        seatAllocated: false, seatReleased: false, effectiveAssignmentRetained: true },
    ] }), {}, removed ? 200 : 201);
  });
});
afterEach(() => clients.splice(0).forEach(client => client.dispose()));
async function client() { const current = new CompanyBlueprintAssignmentsClient(assignmentContext); clients.push(current); await current.access(); return current; }
const input = () => ({ userId: id(5), blueprintId: id(2), version: 1 });
test('reads complete pinned bindings and validates actual assignment ETag', async () => {
  const current = await client(); expect((await current.list(id(5))).assignments[0].version).toBe(1);
  expect((await current.get(id(1))).revision).toBe('1'); expect((await current.effective(id(5))).applications[0].sources).toHaveLength(2);
  expect(api.post).not.toHaveBeenCalled();
});
test('captures immutable released version and all server pool revisions without reserving another seat on overlap', async () => {
  const current = await client(); const value = await current.preview(input(), [id(20)]); const intent = current.captureAssign(value, 'Geprüfte Mitarbeiterzuweisung');
  expect(intent.body).toMatchObject({ blueprintId: id(2), version: 1, eligibilityRevision: '9007199254740993', pools: [{ poolId: id(20), poolRevision: '9007199254740993' }] });
  expect(Object.isFrozen(intent.body.pools)).toBe(true); const receipt = await current.write(intent); expect(receipt.pools[0].seatAllocated).toBe(false);
  expect((api.post as jest.Mock).mock.calls[0][1]).toEqual(input()); expect((api.post as jest.Mock).mock.calls[1][2].headers).toEqual({ 'Idempotency-Key': intent.operationId });
});
test('negative target removal uses exact server removal preview and original binding ETag, not positive assignment preview', async () => {
  const current = await client(); const value = await current.removalPreview(id(1)); const intent = current.captureRemove(value, 'Nur diesen Blueprint zurücknehmen');
  await current.write(intent);
  expect(intent.body).toMatchObject({ userId: id(5), eligibilityRevision: '9007199254740994' });
  expect(api.post).toHaveBeenCalledWith(base + '/' + id(1) + '/remove', intent.body, expect.objectContaining({ headers: { 'Idempotency-Key': intent.operationId, 'If-Match': companyBlueprintAssignmentEtag(binding) } }));
  expect((api.post as jest.Mock).mock.calls.some(([url]) => url.endsWith('/preview'))).toBe(false);
});
test('retains the exact original operation, body and ETag after an unconfirmed reply', async () => {
  const current = await client(); const value = await current.removalPreview(id(1)); const intent = current.captureRemove(value, 'Nur diesen Blueprint zurücknehmen');
  (api.post as jest.Mock).mockRejectedValueOnce(new Error('network')); await expect(current.write(intent)).rejects.toThrow();
  expect(current.canRetry(intent)).toBe(true); await current.write(intent);
  const calls = (api.post as jest.Mock).mock.calls; expect(calls[1][1]).toBe(calls[0][1]); expect(calls[1][2].headers).toEqual(calls[0][2].headers);
});
test.each([
  ['wrong protocol', (value: any) => { value.companyBlueprintAssignmentsProtocol = 2; }],
  ['borrowed old permissions', (value: any) => { value.permissions = ['company.blueprints.read', 'company.blueprints.manage', 'company.blueprints.publish']; }],
  ['global privilege', (value: any) => { value.permissions.push('policies.deploy'); }],
  ['fake MDM mode', (value: any) => { value.configurationMode = 'mdm'; }], ['other actor', (value: any) => { value.actorUserId = id(99); }],
])('rejects capability %s', async (_name, change) => { change(access); await expect(client()).rejects.toThrow(); expect(api.post).not.toHaveBeenCalled(); });
test.each([
  ['other target', (value: any) => { value.userId = id(6); }], ['head instead of pinned version', (value: any) => { value.version = 2; }],
  ['missing pool', (value: any) => { value.pools = []; }], ['duplicate pool', (value: any) => { value.pools.push(value.pools[0]); }],
  ['inconsistent stock', (value: any) => { value.pools[0].availableSeats = 1; }], ['numeric revision', (value: any) => { value.pools[0].poolRevision = 2; }],
  ['lying conflict flag', (value: any) => { value.hasConflicts = true; }], ['secret payload', (value: any) => { value.effectiveConfigurations[0].payloadJson = '{"secret":"value"}'; }],
  ['duplicate configuration source', (value: any) => { value.effectiveConfigurations[0].sources.push(value.effectiveConfigurations[0].sources[0]); }],
])('rejects assignment preview %s', async (_name, change) => { const current = await client(); change(preview); await expect(current.preview(input(), [id(20)])).rejects.toThrow(); });
test('blocks an actual additional seat shortage even when the pool is otherwise valid', async () => {
  const current = await client(); preview.pools[0].additionalSeats = 1; const value = await current.preview(input(), [id(20)]);
  expect(() => current.captureAssign(value, 'Geprüfte Mitarbeiterzuweisung')).toThrow(); expect(api.post).toHaveBeenCalledTimes(1);
});
test('accepts a configuration-only assignment with zero license children', async () => {
  const current = await client(); preview.pools = []; const value = await current.preview(input(), []); const intent = current.captureAssign(value, 'Nur sichere lokale Vorgaben');
  (api.post as jest.Mock).mockResolvedValueOnce(ok(envelope({ operationId: intent.operationId, assignmentId: intent.assignmentId, action: 'assigned', outcome: 'applied', revision: '1', deliveryStatus: 'pending', pools: [] }), {}, 201));
  expect((await current.write(intent)).pools).toEqual([]);
});
test.each([undefined, 'W/"wrong"', '"company-blueprint-assignment-wrong-1"'])('rejects a nonmatching removal ETag %s', async etag => {
  const current = await client(); const original = (api.get as jest.Mock).getMockImplementation();
  (api.get as jest.Mock).mockImplementation(async (url, config) => { const result = await original(url, config); return url.endsWith('/removal-preview') ? { ...result, headers: { etag } } : result; });
  await expect(current.removalPreview(id(1))).rejects.toThrow();
});
test('does not fetch any user profiles when the independent directory permission is absent', async () => {
  const current = await client(); expect(await current.users()).toBeNull(); expect((api.get as jest.Mock).mock.calls.some(([url]) => url === '/api/users')).toBe(false);
});
test('rejects forged, copied or post-session intents without sending a write', async () => {
  const current = await client(); const value = await current.preview(input(), [id(20)]); const intent = current.captureAssign(value, 'Geprüfte Mitarbeiterzuweisung');
  await expect(current.write({ ...intent })).rejects.toThrow(); current.invalidate(); await expect(current.write(intent)).rejects.toThrow(); expect(api.post).toHaveBeenCalledTimes(1);
});
