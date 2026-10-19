import { actorUserId, context, createdAt, otherId, reason, userId, workflowId } from './companyOffboarding';

export const groupsBase = '/api/users/' + userId + '/company-offboarding-groups';
export const groupsBinding = { ...context, workflowId, userId, eligibilityRevision: '8' };
export const groupIdAt = (index: number) => 'aaaaaaaa-aaaa-4aaa-8aaa-' + String(index + 1).padStart(12, '0');
export const membershipIdAt = (index: number) => 'bbbbbbbb-bbbb-4bbb-8bbb-' + String(index + 1).padStart(12, '0');
export const groupOperationIdAt = (index: number) => 'cccccccc-cccc-4ccc-8ccc-' + String(index + 1).padStart(12, '0');
export const groupFixture = (index = 0, changes: Record<string, unknown> = {}) => ({
  groupId: groupIdAt(index), name: 'Austrittsgruppe ' + (index + 1), groupRevision: '9007199254740993', membershipId: membershipIdAt(index), ...changes,
});
export const groupsPreviewFixture = (changes: Record<string, unknown> = {}) => ({
  schemaVersion: 1, companyOffboardingGroupsProtocol: 1, ...context, workflowId, userId,
  target: { enabled: false, eligibilityRevision: '8' }, groups: [groupFixture()], total: 1, page: 1, limit: 25, ...changes,
});
export const groupReceiptFixture = (index = 0, changes: Record<string, unknown> = {}) => ({
  id: 'dddddddd-dddd-4ddd-8ddd-' + String(index + 1).padStart(12, '0'), groupId: groupIdAt(index), name: 'Austrittsgruppe ' + (index + 1),
  membershipId: membershipIdAt(index), operationId: groupOperationIdAt(index), beforeGroupRevision: '9007199254740993', afterGroupRevision: '9007199254740994',
  actorUserId, reason, createdAt, deliveryStatus: 'pending', ...changes,
});
export const groupsHistoryFixture = (changes: Record<string, unknown> = {}) => ({
  schemaVersion: 1, ...context, workflowId, userId, target: { enabled: false, eligibilityRevision: '8' }, receipts: [], total: 0, page: 1, limit: 25, ...changes,
});
export const groupResultFixture = (index = 0, changes: Record<string, unknown> = {}) => ({
  groupId: groupIdAt(index), membershipId: membershipIdAt(index), status: 'removed', code: 200, operationId: groupOperationIdAt(index), ...changes,
});
export const groupsOutcomeFixture = (changes: Record<string, unknown> = {}) => ({
  schemaVersion: 1, ...context, workflowId, userId, correlationId: otherId, results: [groupResultFixture()], ...changes,
});
export function deferred<Value>() {
  let resolve: (value: Value) => void;
  let reject: (error: unknown) => void;
  const promise = new Promise<Value>((finish, fail) => { resolve = finish; reject = fail; });
  return { promise, resolve, reject };
}
