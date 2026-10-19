export const actorUserId = '11111111-1111-4111-8111-111111111111';
export const tenantId = '22222222-2222-4222-8222-222222222222';
export const userId = '33333333-3333-4333-8333-333333333333';
export const workflowId = '44444444-4444-4444-8444-444444444444';
export const poolId = '55555555-5555-4555-8555-555555555555';
export const assignmentId = '66666666-6666-4666-8666-666666666666';
export const grantId = '77777777-7777-4777-8777-777777777777';
export const operationId = '88888888-8888-4888-8888-888888888888';
export const otherId = '99999999-9999-4999-8999-999999999999';
export const createdAt = '2026-10-19T10:00:00.000Z';
export const reason = 'Geprüfter Austritt des Mitarbeiters';
export const requestedRevision = '9007199254740993';
export const context = { actorUserId, tenantId };
export const base = '/api/licenses/company';
export const jobs = base + '/offboarding-workflows';
export const capabilitiesFixture = (changes = {}) => ({ schemaVersion: 1, ...context, companyOffboardingProtocol: 1, scope: 'account-and-local-licenses', requiresFreshMfa: true, ...changes });
export const previewFixture = (userChanges = {}) => ({ schemaVersion: 1, ...context, user: { id: userId, name: 'Anna Beispiel', userRevision: requestedRevision, eligibilityRevision: '7', enabled: true, ...userChanges }, licenseCount: 26 });
export const itemFixture = (changes = {}) => ({ poolId, assignmentId, grantId, poolRevision: '9007199254740995', name: 'Firmen Editor', vendor: 'Firmen Anbieter', ...changes });
export const jobFixture = (workflowChanges = {}, targetChanges = {}): any => ({
  schemaVersion: 1, ...context,
  workflow: { id: workflowId, userId, createdBy: actorUserId, revision: '2', reason, phase: 'licenses', totalLicenses: 26, completedLicenses: 25, failure: null, createdAt, updatedAt: createdAt,
    requestedRevision, checkpoint: { schemaVersion: 1, workflowId, tenantId, userId, actorUserId, operationId, action: 'disabled', beforeRevision: requestedRevision, afterRevision: '9007199254740994', beforeEligibilityRevision: '7', afterEligibilityRevision: '8', createdAt, deliveryStatus: 'pending' },
    nextAssignments: [itemFixture()], reviewAssignments: [], ...workflowChanges },
  currentTarget: { enabled: false, deleted: false, eligibilityRevision: '8', ...targetChanges },
});
export const pendingFixture = (changes = {}) => jobFixture({ phase: 'pending', checkpoint: null, totalLicenses: null, completedLicenses: 0, nextAssignments: [], ...changes }, { enabled: true, eligibilityRevision: '7' });
export const completedFixture = (changes = {}) => jobFixture({ phase: 'completed_local', revision: '3', completedLicenses: 26, nextAssignments: [], ...changes });
export function summaryFixture(job = jobFixture()) {
  const { requestedRevision: requested, checkpoint, nextAssignments, reviewAssignments, ...summary } = job.workflow;
  return summary;
}
export const queueFixture = (job = jobFixture()) => ({ schemaVersion: 1, ...context, workflows: [summaryFixture(job)], total: 1, page: 1, limit: 25 });
export const historyFixture = (job = jobFixture()) => ({ schemaVersion: 1, ...context, workflowId: job.workflow.id, events: [{ id: otherId, revision: job.workflow.revision, phase: job.workflow.phase, actorUserId, createdAt, deliveryStatus: 'pending', failure: job.workflow.failure, completedLicenses: job.workflow.completedLicenses, totalLicenses: job.workflow.totalLicenses }], total: 1, page: 1, limit: 25 });
