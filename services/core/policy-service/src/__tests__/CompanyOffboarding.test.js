'use strict';

const { randomUUID } = require('node:crypto');
const { CompanyOffboarding } = require('../licenses/CompanyOffboarding');
const { offboardingEtag } = require('../../../../../packages/company-license-contract');
let service; let companies; let journal; let identity; let actor; let source; let target; let job; let intent; let items; let released;
const authorization = 'Bearer original.offboarding';
beforeEach(() => {
  const actorUserId = randomUUID(); const userId = randomUUID(); const now = new Date().toISOString(); actor = { identity_authorization: { userId: actorUserId } };
  source = { actorUserId, tenant: { id: randomUUID() }, context: actor.identity_authorization, validUntil: Math.floor(Date.now() / 1000) + 300, target: null };
  target = { id: userId, enabled: true, deleted: false, revision: '5', eligibilityRevision: '104' };
  intent = { workflowId: randomUUID(), userId, userRevision: '8', eligibilityRevision: '104', reason: 'Confirmed own employee local offboarding', confirm: true };
  job = { id: intent.workflowId, tenantId: source.tenant.id, userId, createdBy: actorUserId, revision: '1', intent, state: { phase: 'pending', requestedRevision: '8', checkpoint: null, items: null, failure: null }, createdAt: now, updatedAt: now };
  items = Array.from({ length: 2 }, () => ({ poolId: randomUUID(), assignmentId: randomUUID(), grantId: randomUUID(), poolRevision: '2', name: 'Actual local app', vendor: 'Actual vendor', status: 'pending', eventId: null })); released = new Map();
  const query = jest.fn(async () => ({ rows: [{ total: 0 }] })); const client = { query };
  companies = { database: client, authority: { read: jest.fn(async (_bearer, _actor, id) => ({ ...source, target: id ? structuredClone(target) : null })) }, unchanged: jest.fn(async () => ({})),
    read: jest.fn(async (_actor, _bearer, operation) => operation(client, { ...source, target: structuredClone(target) })), ownPool: jest.fn(async () => ({ business_revision: '2' })),
    revoke: jest.fn(async (_poolId, assignmentId) => released.set(assignmentId, randomUUID())) };
  journal = { ready: jest.fn(), lock: jest.fn(async () => ({ client, release: jest.fn() })), load: jest.fn(async () => null), create: jest.fn(async () => ({ job: structuredClone(job), created: true })),
    save: jest.fn(async (_client, proof, previous, state, verify) => { await verify(); job = { ...previous, state: structuredClone(state), revision: String(BigInt(previous.revision) + 1n) }; return structuredClone(job); }) };
  identity = { user: jest.fn(async () => ({ id: userId, name: 'Employee', userRevision: '8', eligibilityRevision: target.eligibilityRevision, enabled: target.enabled })),
    disable: jest.fn(async () => { target = { ...target, enabled: false, revision: '19', eligibilityRevision: '187' }; return { schemaVersion: 1, workflowId: job.id, tenantId: source.tenant.id, userId, actorUserId, operationId: randomUUID(), action: 'disabled', beforeRevision: '8', afterRevision: '21', beforeEligibilityRevision: '104', afterEligibilityRevision: '187', createdAt: now, deliveryStatus: 'pending' }; }) };
  service = new CompanyOffboarding(companies, { journal, identity }); service.capture = jest.fn(async () => structuredClone(items));
  service.observe = jest.fn(async (_job, item) => released.has(item.assignmentId) ? { ...item, status: 'released', eventId: released.get(item.assignmentId) } : null);
});
test('self offboarding cannot create durable intent or call an account endpoint', async () => {
  intent.userId = source.actorUserId;
  await expect(service.create(intent, actor, authorization)).rejects.toMatchObject({ status: 403 });
  expect(journal.create).not.toHaveBeenCalled(); expect(identity.disable).not.toHaveBeenCalled(); expect(companies.revoke).not.toHaveBeenCalled();
});
test('a stale employee preview cannot create a journal or disable the account', async () => {
  intent.userRevision = '7'; await expect(service.create(intent, actor, authorization)).rejects.toMatchObject({ status: 412 });
  expect(journal.create).not.toHaveBeenCalled(); expect(identity.disable).not.toHaveBeenCalled();
});
test('confirmed account disable is durable before capture and each real license release, without assuming a per-user +1 generation', async () => {
  const result = await service.create(intent, actor, authorization);
  expect(result.created).toBe(true); expect(result.result.workflow.phase).toBe('completed_local'); expect(result.result.workflow.completedLicenses).toBe(2);
  expect(result.result.currentTarget).toEqual({ enabled: false, deleted: false, eligibilityRevision: '187' });
  expect(journal.save.mock.calls.map(call => call[3].phase)).toEqual(['licenses', 'licenses', 'licenses', 'licenses', 'completed_local']);
  expect(companies.revoke).toHaveBeenCalledTimes(2); expect(companies.revoke.mock.calls.every(call => call[6] === intent.workflowId && call[7].target.eligibilityRevision === '187')).toBe(true);
});
test('lost create response recovers the same original journal and never repeats account or license actions', async () => {
  journal.load.mockResolvedValue({ ...job, intent: { ...intent } });
  const result = await service.create(intent, actor, authorization); expect(result.created).toBe(false);
  expect(journal.create).not.toHaveBeenCalled(); expect(identity.disable).not.toHaveBeenCalled(); expect(companies.revoke).not.toHaveBeenCalled();
});
test('same id with a changed intent cannot silently start another employee workflow', async () => {
  journal.load.mockResolvedValue({ ...job, intent: { ...intent } }); await expect(service.create({ ...intent, reason: 'Another incompatible requested intent' }, actor, authorization)).rejects.toMatchObject({ status: 409 });
  expect(identity.disable).not.toHaveBeenCalled();
});
test('a later employee generation cannot be disabled before the old workflow checks its captured lifecycle', async () => {
  target.eligibilityRevision = '211'; journal.load.mockResolvedValue(structuredClone(job));
  const result = await service.continue(job.id, { confirm: true, reason: intent.reason, userRevision: '8', assignments: [] }, offboardingEtag(job), actor, authorization);
  expect(result.workflow.phase).toBe('paused'); expect(result.workflow.failure).toEqual({ code: 409, step: 'verify' });
  expect(identity.disable).not.toHaveBeenCalled(); expect(companies.revoke).not.toHaveBeenCalled();
});
test('a late license conflict retains earlier confirmed progress and stops before the next license', async () => {
  companies.revoke.mockImplementationOnce(async (_poolId, id) => released.set(id, randomUUID())).mockRejectedValueOnce(Object.assign(new Error('captured version changed'), { status: 412 }));
  const result = await service.create(intent, actor, authorization);
  expect(result.result.workflow.phase).toBe('paused'); expect(result.result.workflow.completedLicenses).toBe(1); expect(result.result.workflow.failure).toEqual({ code: 412, step: 'licenses' });
  expect(target.enabled).toBe(false); expect(identity.disable).toHaveBeenCalledTimes(1);
});
test('remaining uncaptured assignments prevent a completed-local report', async () => {
  companies.database.query.mockResolvedValue({ rows: [{ total: 1 }] }); const result = await service.create(intent, actor, authorization);
  expect(result.result.workflow.phase).toBe('paused'); expect(result.result.workflow.failure).toEqual({ code: 409, step: 'verify' });
});
test('a changed actor during recovery withholds even a partially committed result', async () => {
  companies.revoke.mockRejectedValueOnce(Object.assign(new Error('source lost'), { status: 401 }));
  service.source = jest.fn().mockImplementation(async (_user, _bearer, id) => ({ ...source, ...(companies.revoke.mock.calls.length ? { context: { ...source.context, revision: 'changed' } } : {}), target: id ? structuredClone(target) : null }));
  await expect(service.create(intent, actor, authorization)).rejects.toMatchObject({ status: 401 });
  expect(companies.revoke).toHaveBeenCalledTimes(1);
});
test('a stale workflow ETag and a foreign workflow are denied before account or recipient transport', async () => {
  journal.load.mockResolvedValueOnce(structuredClone(job)).mockResolvedValueOnce(null);
  const body = { confirm: true, reason: intent.reason, userRevision: '8', assignments: [] };
  await expect(service.continue(job.id, body, offboardingEtag({ ...job, revision: '2' }), actor, authorization)).rejects.toMatchObject({ status: 412 });
  await expect(service.continue(job.id, body, offboardingEtag(job), actor, authorization)).rejects.toMatchObject({ status: 404 });
  expect(identity.disable).not.toHaveBeenCalled(); expect(identity.user).not.toHaveBeenCalled();
});
test('workflow listing sends only accepted numeric pagination fields to the durable journal', async () => {
  journal.list = jest.fn(async () => ({ jobs: [job], total: 1, page: 1, limit: 25 }));
  const result = await service.list({}, actor, authorization);
  expect(result.workflows[0].id).toBe(job.id); expect(journal.list).toHaveBeenCalledWith(companies.database, source.tenant.id, { page: 1, limit: 25 });
});
test('history preserves its exact tenant/workflow boundary and does not add an unsupported search selector', async () => {
  journal.load.mockResolvedValue(job); journal.history = jest.fn(async () => ({ events: [], total: 0, page: 1, limit: 25 }));
  const result = await service.history(job.id, {}, actor, authorization);
  expect(result.workflowId).toBe(job.id); expect(journal.history).toHaveBeenCalledWith(companies.database, source.tenant.id, job.id, { page: 1, limit: 25 });
});
