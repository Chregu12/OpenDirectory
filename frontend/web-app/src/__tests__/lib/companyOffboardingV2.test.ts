import { api } from '@/lib/api';
import { CompanyOffboardingV2Client, companyOffboardingV2Etag } from '@/lib/companyOffboardingV2';
import { assignmentId as id, assignmentContext, assignmentOffboardAccess, assignmentOffboardPreview, assignmentOffboardJob,
  assignmentReturnRow, assignmentV2Envelope as envelope, assignmentOk as ok, assignmentDirect } from '../fixtures/companyAssignmentsV2';

jest.mock('@/lib/api', () => ({ api: { get: jest.fn(), post: jest.fn() } }));
const base = '/api/licenses/company/v2'; const jobs = base + '/offboarding-workflows'; const clients: CompanyOffboardingV2Client[] = [];
let job: ReturnType<typeof assignmentOffboardJob>; let preview: ReturnType<typeof assignmentOffboardPreview>; let sequence: number;
beforeEach(() => {
  jest.resetAllMocks(); job = assignmentOffboardJob(); preview = assignmentOffboardPreview(); sequence = 100;
  Object.defineProperty(crypto, 'randomUUID', { configurable: true, value: jest.fn(() => id(sequence++)) });
  (api.get as jest.Mock).mockImplementation(async (url: string) => {
    if (url.endsWith('/capabilities')) return ok(assignmentOffboardAccess());
    if (url.endsWith('/offboarding-preview')) return ok(preview);
    if (url === jobs + '/' + id(80)) return ok(job, { etag: companyOffboardingV2Etag(job.workflow) });
    if (url === jobs) { const { requestedRevision, checkpoint, nextAssignments, reviewAssignments, nextBindings, ...summary } = job.workflow;
      return ok(envelope({ workflows: [summary], total: 1, page: 1, limit: 25 })); }
    if (url.endsWith('/history')) return ok(envelope({ workflowId: id(80), events: [], total: 0, page: 1, limit: 25 }));
    throw new Error('Unexpected read ' + url);
  });
  (api.post as jest.Mock).mockImplementation(async (_url: string, _body: any, _config: any) => {
    const completed = JSON.parse(JSON.stringify(job)); completed.workflow.phase = 'completed_local'; completed.workflow.revision = '4';
    completed.workflow.completedLicenses = completed.workflow.totalLicenses; completed.workflow.completedBindings = completed.workflow.totalBindings;
    completed.workflow.nextAssignments = []; completed.workflow.nextBindings = []; completed.workflow.reviewAssignments = [];
    return ok(completed);
  });
});
afterEach(() => clients.splice(0).forEach(current => current.dispose()));
async function client() { const current = new CompanyOffboardingV2Client(assignmentContext); clients.push(current); await current.access(); return current; }
test('captures and retires a zero-app binding instead of falsely completing at zero licenses', async () => {
  const current = await client(); const value = await current.get(id(80)); const intent = current.captureContinue(value);
  expect(intent.body).toEqual({ confirm: true, reason: 'Bewusster Mitarbeiteraustritt', userRevision: '99', assignments: [], bindings: [{ id: id(1), revision: '1' }] });
  const result = await current.write(intent); expect(result.workflow).toMatchObject({ phase: 'completed_local', totalLicenses: 0, completedLicenses: 0, totalBindings: 1, completedBindings: 1 });
  expect(api.post).toHaveBeenCalledWith(jobs + '/' + id(80) + '/continue', intent.body, expect.objectContaining({ headers: { 'Idempotency-Key': intent.operationId, 'If-Match': companyOffboardingV2Etag(value.workflow) } }));
});
test('preserves all 26 pools and sources in one atomic captured continuation rather than paging offboarding at 25', async () => {
  job.workflow.totalLicenses = 26; job.workflow.nextAssignments = Array.from({ length: 26 }, (_, index) => ({ ...assignmentReturnRow(index + 20), sources: [{ ...assignmentDirect(), grantId: id(200 + index) }] }));
  const current = await client(); const value = await current.get(id(80)); const intent = current.captureContinue(value);
  expect((intent.body.assignments as unknown[])).toHaveLength(26); await current.write(intent); expect(api.post).toHaveBeenCalledTimes(1);
});
test('cannot silently turn an old single-grant capture into an all-source manifest', async () => {
  job.workflow.totalLicenses = 1; job.workflow.nextAssignments = [{ ...assignmentReturnRow(), sources: [] }];
  const current = await client(); await expect(current.get(id(80))).rejects.toThrow(); expect(api.post).not.toHaveBeenCalled();
});
test.each([
  ['false completion while binding remains', (value: any) => { value.workflow.phase = 'completed_local'; }],
  ['truncated pool capture', (value: any) => { value.workflow.totalLicenses = 26; }],
  ['truncated zero-app binding capture', (value: any) => { value.workflow.totalBindings = 2; }],
  ['borrowed checkpoint', (value: any) => { value.workflow.checkpoint.workflowId = id(82); }],
  ['positive checkpoint', (value: any) => { value.workflow.checkpoint.afterEligibilityRevision = value.workflow.checkpoint.beforeEligibilityRevision; }],
  ['wrong negative target', (value: any) => { value.currentTarget = { enabled: true, deleted: true, eligibilityRevision: '1' }; }],
  ['unbounded total', (value: any) => { value.workflow.totalBindings = 10001; }],
  ['missing binding source revision', (value: any) => { delete value.workflow.nextBindings[0].revision; }],
  ['invented provider success', (value: any) => { value.mdmSuccess = true; }],
  ['V1 protocol', (value: any) => { value.companyLicenseProtocol = 1; }],
])('rejects unproven offboarding %s', async (_name, change) => { const current = await client(); change(job); await expect(current.get(id(80))).rejects.toThrow(); });
test.each(['reactivated', 'new negative generation'])('does not continue an old capture for %s', async state => {
  if (state === 'reactivated') job.currentTarget.enabled = true; else job.currentTarget.eligibilityRevision = '9007199254740995';
  const current = await client(); const value = await current.get(id(80)); expect(() => current.captureContinue(value)).toThrow(); expect(api.post).not.toHaveBeenCalled();
});
test('refuses deleted-target workflow continuation without canonical lifecycle history even if a stub repeats the old negative generation', async () => {
  job.currentTarget.deleted = true; const current = await client(); const value = await current.get(id(80)); expect(() => current.captureContinue(value)).toThrow(); expect(api.post).not.toHaveBeenCalled();
});
test('keeps a historical completed workflow readable after deletion without allowing any new mutation', async () => {
  job.workflow.phase = 'completed_local'; job.workflow.completedBindings = 1; job.workflow.nextBindings = []; job.currentTarget.deleted = true;
  const current = await client(); const value = await current.get(id(80)); expect(value.workflow.phase).toBe('completed_local');
  expect(() => current.captureContinue(value)).toThrow(); expect(api.post).not.toHaveBeenCalled();
});
test('does not accept a forged preview or a copied job as a source for new effects', async () => {
  const current = await client(); const value = await current.get(id(80)); const observed = await current.preview(id(5));
  expect(() => current.captureContinue({ ...value })).toThrow(); expect(() => current.captureCreate({ ...observed }, 'Bewusster Mitarbeiteraustritt')).toThrow(); expect(api.post).not.toHaveBeenCalled();
});
test('new workflow uses the exact server eligibility and one stable workflow/idempotency UUID', async () => {
  const current = await client(); const value = await current.preview(id(5)); const intent = current.captureCreate(value, 'Bewusster Mitarbeiteraustritt');
  expect(intent.operationId).toBe(intent.workflowId); expect(intent.body).toEqual({ workflowId: intent.workflowId, userId: id(5), userRevision: '99', eligibilityRevision: '9007199254740993', reason: 'Bewusster Mitarbeiteraustritt', confirm: true });
  expect(api.post).not.toHaveBeenCalled();
});
test('unknown continuation result retains the original checkpoint, operation UUID, body and old workflow ETag', async () => {
  const current = await client(); const value = await current.get(id(80)); const intent = current.captureContinue(value);
  (api.post as jest.Mock).mockRejectedValueOnce(new Error('network')); await expect(current.write(intent)).rejects.toThrow(); expect(current.canRetry(intent)).toBe(true);
  await current.write(intent); const calls = (api.post as jest.Mock).mock.calls; expect(calls[1][1]).toBe(calls[0][1]); expect(calls[1][2].headers).toEqual(calls[0][2].headers);
});
test('rejects a returned workflow whose target was swapped after a legitimate continuation', async () => {
  const current = await client(); const value = await current.get(id(80)); const intent = current.captureContinue(value);
  const original = (api.post as jest.Mock).getMockImplementation(); (api.post as jest.Mock).mockImplementation(async (...args) => { const result = await original(...args); result.data.workflow.userId = id(6); result.data.workflow.checkpoint.userId = id(6); return result; });
  await expect(current.write(intent)).rejects.toThrow();
});
test('a historical completion cannot refresh the original account checkpoint', async () => {
  const current = await client(); const value = await current.get(id(80)); const intent = current.captureContinue(value);
  const original = (api.post as jest.Mock).getMockImplementation(); (api.post as jest.Mock).mockImplementation(async (...args) => { const result = await original(...args); result.data.workflow.checkpoint.afterEligibilityRevision = '9007199254740995'; return result; });
  await expect(current.write(intent)).rejects.toThrow();
});
test('session invalidation prevents any original workflow mutation without new explicit inspection', async () => {
  const current = await client(); const value = await current.get(id(80)); const intent = current.captureContinue(value); window.dispatchEvent(new Event('od:session-error'));
  await expect(current.write(intent)).rejects.toThrow(); expect(api.post).not.toHaveBeenCalled();
});
