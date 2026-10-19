import { companySourcesSchema, companyRevision, CompanyWorkflowSession, companyUuid } from '@/lib/companyAssignmentProtocol';
import { z } from 'zod';
import { api } from '@/lib/api';
import { assignmentContext, assignmentDirect, assignmentBlueprintSource, assignmentDeferred, assignmentOk } from '../fixtures/companyAssignmentsV2';

jest.mock('@/lib/api', () => ({ api: { get: jest.fn() } }));
const capabilities = z.object({ actorUserId: companyUuid, tenantId: companyUuid }).strict();
const sessions: CompanyWorkflowSession<typeof assignmentContext>[] = [];
beforeEach(() => { jest.resetAllMocks(); (api.get as jest.Mock).mockResolvedValue(assignmentOk(assignmentContext)); });
afterEach(() => sessions.splice(0).forEach(session => session.dispose()));
function session() { const value = new CompanyWorkflowSession('/capabilities', capabilities, assignmentContext); sessions.push(value); return value; }
test('preserves sorted complete blueprint and manual source identities', () => {
  expect(companySourcesSchema.parse([assignmentBlueprintSource(), assignmentDirect()])).toEqual([assignmentBlueprintSource(), assignmentDirect()]);
});
test.each([
  [], [assignmentDirect(), assignmentBlueprintSource()], [assignmentDirect(), assignmentDirect()],
  [{ ...assignmentDirect(), sourceId: assignmentBlueprintSource().sourceId }], [{ ...assignmentBlueprintSource(), sourceId: 'direct' }],
  [{ ...assignmentDirect(), sourceType: 'group' }], [{ ...assignmentDirect(), grantId: 'wrong' }],
  [assignmentBlueprintSource(), { ...assignmentDirect(), grantId: assignmentBlueprintSource().grantId }],
  [{ ...assignmentDirect(), secret: 'not-allowed' }],
].map(value => [value]))('rejects malformed or incomplete source manifest %j', value => { expect(companySourcesSchema.safeParse(value).success).toBe(false); });
test.each(['0', '01', '9223372036854775808', '1\n', '1.0', 1])('rejects unsafe revision %j', value => { expect(companyRevision.safeParse(value).success).toBe(false); });
test('retains precision above Number.MAX_SAFE_INTEGER', () => { expect(companyRevision.parse('9007199254740993')).toBe('9007199254740993'); });
test('captures deeply frozen objects and rejects copied identities', async () => {
  const current = session(); await current.access(); const captured = current.own({ sources: [assignmentDirect()] });
  expect(Object.isFrozen(captured.sources[0])).toBe(true); expect(current.captured(captured)).toBe(true); expect(current.captured({ ...captured })).toBe(false);
  current.invalidate(); expect(current.captured(captured)).toBe(false);
});
test.each([401, 403, 428])('invalidates captured writes after authority status %s', async status => {
  const current = session(); await current.access(); const intent = current.own({});
  (api.get as jest.Mock).mockRejectedValueOnce({ response: { status } });
  await expect(current.write(intent, async () => 'unexpected')).rejects.toBeDefined(); expect(current.captured(intent)).toBe(false);
});
test('does not automatically replay an unconfirmed write and retains only the original in-session intent', async () => {
  const current = session(); await current.access(); const intent = current.own({}); const operation = jest.fn().mockRejectedValue(new Error('network'));
  await expect(current.write(intent, operation)).rejects.toThrow('network'); expect(operation).toHaveBeenCalledTimes(1); expect(current.captured(intent)).toBe(true);
});
test('rejects changed tenant before invoking a write', async () => {
  const current = session(); await current.access(); const intent = current.own({}); const operation = jest.fn();
  (api.get as jest.Mock).mockResolvedValueOnce(assignmentOk({ ...assignmentContext, tenantId: assignmentContext.actorUserId }));
  await expect(current.write(intent, operation)).rejects.toThrow(); expect(operation).not.toHaveBeenCalled(); expect(current.captured(intent)).toBe(false);
});
test('session error aborts an in-flight read and ignores its late response', async () => {
  const current = session(); const pending = assignmentDeferred<ReturnType<typeof assignmentOk>>(); (api.get as jest.Mock).mockReturnValueOnce(pending.promise);
  const result = current.access(); window.dispatchEvent(new Event('od:session-error')); pending.resolve(assignmentOk(assignmentContext));
  await expect(result).rejects.toThrow(); expect((api.get as jest.Mock).mock.calls[0][1].signal.aborted).toBe(true);
});
