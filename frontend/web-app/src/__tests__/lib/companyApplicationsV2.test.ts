import { api } from '@/lib/api';
import { CompanyApplicationsV2Client } from '@/lib/companyApplicationsV2';
import { assignmentId as id, assignmentContext, assignmentAppAccess, assignmentManualPreview, assignmentRow, assignmentV2Envelope as envelope, assignmentOk as ok,
  assignmentBlueprintSource, assignmentDirect, assignmentRetirementBinding } from '../fixtures/companyAssignmentsV2';

jest.mock('@/lib/api', () => ({ api: { get: jest.fn(), post: jest.fn() } }));
const base = '/api/licenses/company/v2'; const clients: CompanyApplicationsV2Client[] = [];
let preview: ReturnType<typeof assignmentManualPreview>; let rows: ReturnType<typeof assignmentRow>[]; let sequence: number;
beforeEach(() => {
  jest.resetAllMocks(); preview = assignmentManualPreview(); rows = [assignmentRow()]; sequence = 100;
  Object.defineProperty(crypto, 'randomUUID', { configurable: true, value: jest.fn(() => id(sequence++)) });
  (api.get as jest.Mock).mockImplementation(async (url: string) => {
    if (url.endsWith('/capabilities')) return ok(assignmentAppAccess());
    if (url.endsWith('/assignments')) return ok(envelope({ poolId: id(20), poolRevision: '9007199254740993', assignments: rows, total: rows.length, page: 1, limit: 25 }));
    if (url.endsWith('/license-returns')) return ok(envelope({ userId: id(5), target: { enabled: false, deleted: false, eligibilityRevision: '9007199254740994' },
      assignments: [], bindings: [assignmentRetirementBinding()], totalBindings: 1, workflowRequired: true, total: 0, page: 1, limit: 25 }));
    throw new Error('Unexpected read ' + url);
  });
  (api.post as jest.Mock).mockImplementation(async (url: string, body: any, config: any) => {
    if (url.endsWith('/assignment-preview')) return ok(preview);
    const removed = url.endsWith('/revoke'); const retained = removed ? body.sources.length > 1 : !!body.assignmentId;
    return ok(envelope({ operationId: config.headers['Idempotency-Key'], outcome: 'applied', action: removed ? 'manual_revoke' : 'manual_assign', poolId: id(20), userId: id(5),
      assignmentId: removed && !retained ? null : id(40), sourceAdded: !removed, sourceRemoved: removed, seatAllocated: !removed && !retained, seatReleased: removed && !retained,
      effectiveAssignmentRetained: retained, eventId: id(60), poolRevision: '9007199254740994', deliveryStatus: 'pending' }), {}, removed ? 200 : 201);
  });
});
afterEach(() => clients.splice(0).forEach(current => current.dispose()));
async function client() { const current = new CompanyApplicationsV2Client(assignmentContext); clients.push(current); await current.access(); return current; }
test('lists one actual seat with all blueprint and manual provenance rather than filtering blueprint-only seats', async () => {
  rows[0].sources = [assignmentBlueprintSource()]; const current = await client(); const page = await current.assignments(id(20));
  expect(page.total).toBe(1); expect(page.assignments[0].sources).toEqual([assignmentBlueprintSource()]); expect(Object.isFrozen(page.assignments[0].sources[0])).toBe(true);
  expect(api.post).not.toHaveBeenCalled();
});
test('manual removal sends the complete captured manifest and retains the blueprint seat', async () => {
  const current = await client(); const value = await current.preview(id(20), id(5)); const intent = current.capture('manual_revoke', value, 'Manuelle Quelle zurücknehmen'); const receipt = await current.write(intent);
  expect(receipt).toMatchObject({ sourceRemoved: true, seatReleased: false, effectiveAssignmentRetained: true, assignmentId: id(40) });
  expect(api.post).toHaveBeenLastCalledWith(base + '/pools/' + id(20) + '/assignments/' + id(40) + '/revoke', { userId: id(5), eligibilityRevision: '9007199254740993',
    sources: [assignmentBlueprintSource(), assignmentDirect()], reason: 'Manuelle Quelle zurücknehmen', confirm: true }, expect.objectContaining({ headers: { 'Idempotency-Key': intent.operationId, 'If-Match': '"company-pool-' + id(20) + '-9007199254740993"' } }));
});
test('manual addition to an existing blueprint-only seat consumes no additional seat even at capacity', async () => {
  preview.assignment.sources = [assignmentBlueprintSource()]; const current = await client(); const value = await current.preview(id(20), id(5));
  const intent = current.capture('manual_assign', value, 'Zusätzliche manuelle Herkunft'); expect(intent.body.assignmentId).toBe(id(40));
  expect((await current.write(intent)).seatAllocated).toBe(false);
});
test('new manual seat uses exact server absence proof and server eligibility, never directory revision', async () => {
  preview.assignment = null; const current = await client(); const value = await current.preview(id(20), id(5)); const intent = current.capture('manual_assign', value, 'Erste manuelle Lizenzzuweisung');
  expect(intent.body).toMatchObject({ assignmentId: null, sources: [], eligibilityRevision: '9007199254740993' }); expect((await current.write(intent)).seatAllocated).toBe(true);
});
test('only removal of the last actual manual source returns a seat', async () => {
  preview.assignment.sources = [assignmentDirect()]; const current = await client(); const value = await current.preview(id(20), id(5));
  const receipt = await current.write(current.capture('manual_revoke', value, 'Letzte Quelle zurückgeben'));
  expect(receipt).toMatchObject({ seatReleased: true, effectiveAssignmentRetained: false, assignmentId: null });
});
test.each(['disabled', 'deleted'])('allows exact negative-target manual source cleanup for %s accounts without positive reactivation', async state => {
  preview.target.enabled = false; preview.target.deleted = state === 'deleted'; preview.target.revision = state === 'deleted' ? null : '100'; preview.target.eligibilityRevision = '9007199254740994';
  const current = await client(); const value = await current.preview(id(20), id(5)); expect(() => current.capture('manual_assign', value, 'Keine neue negative Zuweisung')).toThrow();
  const intent = current.capture('manual_revoke', value, 'Negative manuelle Quelle entfernen'); expect(intent.body.eligibilityRevision).toBe('9007199254740994'); await current.write(intent);
});
test('blueprint-only source cannot be removed through the manual action', async () => {
  preview.assignment.sources = [assignmentBlueprintSource()]; const current = await client(); const value = await current.preview(id(20), id(5));
  expect(() => current.capture('manual_revoke', value, 'Keine geliehene Blueprint-Berechtigung')).toThrow(); expect(api.post).toHaveBeenCalledTimes(1);
});
test.each([
  ['missing source', (value: any) => { value.assignment.sources = []; }], ['wrong source type', (value: any) => { value.assignment.sources[0].sourceType = 'group'; }],
  ['borrowed target', (value: any) => { value.target.id = id(6); }], ['wrong pool', (value: any) => { value.poolId = id(21); }],
  ['stale positive eligibility', (value: any) => { value.assignment.eligibilityRevision = '1'; }], ['numeric eligibility', (value: any) => { value.target.eligibilityRevision = 1; }],
  ['extra authority', (value: any) => { value.platformAdmin = true; }], ['protocol downgrade', (value: any) => { value.companyLicenseProtocol = 1; }],
])('rejects preview %s', async (_name, change) => { const current = await client(); change(preview); await expect(current.preview(id(20), id(5))).rejects.toThrow(); });
test('unconfirmed manual retry keeps the exact operation and old pool ETag', async () => {
  const current = await client(); const value = await current.preview(id(20), id(5)); const intent = current.capture('manual_revoke', value, 'Manuelle Quelle zurücknehmen');
  const original = (api.post as jest.Mock).getMockImplementation(); (api.post as jest.Mock).mockRejectedValueOnce(new Error('network'));
  await expect(current.write(intent)).rejects.toThrow(); expect(current.canRetry(intent)).toBe(true);
  (api.post as jest.Mock).mockImplementation(async (...args) => { const result = await original(...args); return { ...result, data: { ...result.data, outcome: 'already_applied' } }; });
  expect((await current.write(intent)).outcome).toBe('already_applied'); const calls = (api.post as jest.Mock).mock.calls; expect(calls[2][1]).toBe(calls[1][1]); expect(calls[2][2].headers).toEqual(calls[1][2].headers);
});
test('configuration-only bindings require real offboarding even with zero license seats', async () => {
  const current = await client(); const value = await current.returnPreview(id(5)); expect(value.total).toBe(0); expect(value.totalBindings).toBe(1); expect(value.workflowRequired).toBe(true);
  expect(api.post).not.toHaveBeenCalled();
});
test('rejects a fake full seat release when a captured blueprint source must remain', async () => {
  const current = await client(); const value = await current.preview(id(20), id(5)); const intent = current.capture('manual_revoke', value, 'Manuelle Quelle zurücknehmen');
  const original = (api.post as jest.Mock).getMockImplementation(); (api.post as jest.Mock).mockImplementation(async (...args) => { const result = await original(...args); return { ...result, data: { ...result.data, seatReleased: true } }; });
  await expect(current.write(intent)).rejects.toThrow();
});
