'use strict';

const { randomUUID } = require('crypto');
jest.mock('../CompanyLicenseAuthority', () => ({ CompanyLicenseAuthority: jest.fn() }));
jest.mock('../DirectoryAuthority', () => ({ requireDirectoryPermissions: jest.fn(async () => {}) }));
jest.mock('../GroupMutator', () => ({ GroupMutator: jest.fn(), groupEtag: group => `"group-${group.id}-${group.revision}"` }));
const { CompanyLicenseAuthority } = require('../CompanyLicenseAuthority');
const { requireDirectoryPermissions } = require('../DirectoryAuthority');
const { GroupMutator } = require('../GroupMutator');
const { CompanyOffboardingGroups } = require('../CompanyOffboardingGroups');
let user; let source; let userId; let intent; let read; let query; let removeMember; let database; let service;
beforeEach(() => {
  jest.clearAllMocks(); userId = randomUUID(); user = { sub: 'actual-owner', actor_type: 'user', identity_authorization: { userId: randomUUID(), revision: '1', linkRevision: '1', rolesRevision: 'a'.repeat(64) } };
  source = { issuer: 'https://cleanup.test', subject: user.sub, actorUserId: user.identity_authorization.userId, context: user.identity_authorization,
    tenant: { id: randomUUID(), version: '1', generation: '1' }, tokenId: randomUUID(), expiresAt: 9999999999, validUntil: 9999999999,
    target: { id: userId, enabled: false, deleted: false, revision: '10', eligibilityRevision: '9007199254740993' } };
  intent = { workflowId: randomUUID(), eligibilityRevision: source.target.eligibilityRevision, reason: 'Explicit captured group cleanup', confirm: true,
    memberships: Array.from({ length: 3 }, () => ({ groupId: randomUUID(), groupRevision: '9007199254741001', membershipId: randomUUID() })) };
  read = jest.fn(async () => source); CompanyLicenseAuthority.mockImplementation(() => ({ read }));
  removeMember = jest.fn(async () => {}); GroupMutator.mockImplementation(() => ({ removeMember }));
  query = jest.fn(async (sql, values) => {
    if (sql.startsWith('SELECT after_eligibility_revision')) return { rows: [{ after_eligibility_revision: source.target.eligibilityRevision }] };
    if (sql.startsWith('SELECT id,revision FROM groups')) return { rows: [{ id: values[0], revision: intent.memberships.find(member => member.groupId === values[0])?.groupRevision }] };
    if (sql.startsWith('SELECT membership_id FROM group_members')) return { rows: [{ membership_id: values[2] }] };
    if (sql.startsWith('SELECT identity_subject_link_role_state')) return { rows: [{ state: {} }] };
    if (sql.startsWith('INSERT INTO identity_company_offboarding_group_receipts')) return { rows: [{ id: values[0] }] };
    if (sql.startsWith('SELECT count(*)')) return { rows: [{ count: '0' }] };
    return { rows: [] };
  });
  database = { isAvailable: () => true, transaction: jest.fn(async (operation, options = {}) => {
    const client = { query }; const result = await operation(client); await options.beforeCommit?.(client); return result;
  }) };
  service = new CompanyOffboardingGroups(database);
});

test.each([null, [], {}, { tenantId: randomUUID() }, { workflowId: randomUUID(), page: 1 },
  { workflowId: randomUUID(), limit: '24' }, { workflowId: randomUUID(), page: '01' }, { workflowId: randomUUID(), page: '1000001' }])('rejects invalid GET selectors before authority: %j', async queryInput => {
  await expect(service.preview(userId, queryInput, user, 'Bearer original')).rejects.toMatchObject({ status: 400 }); expect(read).not.toHaveBeenCalled();
});
test.each(['tenantId', 'actorUserId', 'correlationId', 'tokenId', 'permissions', 'operationId'])('rejects caller-owned %s before authority', async field => {
  await expect(service.remove(userId, { ...intent, [field]: randomUUID() }, user, 'Bearer original')).rejects.toMatchObject({ status: 400 }); expect(read).not.toHaveBeenCalled();
});
test('rejects noncanonical revisions, duplicates and unconfirmed commands before storage', async () => {
  for (const invalid of [{ ...intent, confirm: false }, { ...intent, memberships: [] }, { ...intent, eligibilityRevision: 1 },
    { ...intent, reason: null }, { ...intent, reason: 'line\nbreak reason' }, { ...intent, memberships: [intent.memberships[0], intent.memberships[0]] },
    { ...intent, memberships: [{ ...intent.memberships[0], groupRevision: '9223372036854775808' }] }])
    await expect(service.remove(userId, invalid, user, 'Bearer original')).rejects.toMatchObject({ status: 400 });
  expect(read).not.toHaveBeenCalled(); expect(query).not.toHaveBeenCalled();
});
test('self is forbidden and missing parent cannot expose groups', async () => {
  await expect(service.preview(user.identity_authorization.userId.toUpperCase(), { workflowId: intent.workflowId }, user, 'Bearer original')).rejects.toMatchObject({ status: 403 });
  const actual = query.getMockImplementation(); query.mockImplementation((sql, values) => sql.startsWith('SELECT after_eligibility_revision') ? { rows: [] } : actual(sql, values));
  await expect(service.remove(userId, intent, user, 'Bearer original')).rejects.toMatchObject({ status: 409 }); expect(removeMember).not.toHaveBeenCalled();
});
test('all manifest items preflight before first mutation and child IDs are server-generated', async () => {
  const result = await service.remove(userId, intent, user, 'Bearer original');
  expect(Object.keys(result)).toEqual(['schemaVersion', 'actorUserId', 'tenantId', 'workflowId', 'userId', 'correlationId', 'results']);
  expect(result.results.map(item => item.status)).toEqual(['removed', 'removed', 'removed']);
  expect(result.results.map(item => [item.groupId, item.membershipId])).toEqual(intent.memberships.map(item => [item.groupId, item.membershipId]));
  expect(new Set(result.results.map(item => item.operationId)).size).toBe(3);
  expect(removeMember).toHaveBeenCalledWith(intent.memberships[0].groupId, userId, `"group-${intent.memberships[0].groupId}-${intent.memberships[0].groupRevision}"`, user, 'Bearer original');
  expect(GroupMutator.mock.calls[0][1].newOperationId()).toBe(result.results[0].operationId);
  expect(requireDirectoryPermissions).toHaveBeenCalledWith(expect.anything(), user, ['groups.read', 'groups.members.manage']);
  const firstBegin = query.mock.calls.findIndex(([sql]) => sql.startsWith('SELECT identity_company_offboarding_groups_begin'));
  expect(query.mock.calls.slice(0, firstBegin).filter(([sql]) => sql.startsWith('SELECT membership_id FROM group_members')).length).toBe(4);
  expect(database.transaction.mock.calls[0][1].readOnly).toBe(true);
});
test('later stale preflight aborts all effects', async () => {
  const actual = query.getMockImplementation(); query.mockImplementation((sql, values) => sql.startsWith('SELECT id,revision FROM groups') && values[0] === intent.memberships[2].groupId
    ? { rows: [{ id: values[0], revision: '1' }] } : actual(sql, values));
  await expect(service.remove(userId, intent, user, 'Bearer original')).rejects.toMatchObject({ status: 412 }); expect(removeMember).not.toHaveBeenCalled();
});
test('each child commits independently; first uncertain child stops the remainder', async () => {
  removeMember.mockResolvedValueOnce({}).mockRejectedValueOnce(Object.assign(new Error('Child conflict'), { status: 409 }));
  const result = await service.remove(userId, intent, user, 'Bearer original');
  expect(result.results.map(item => [item.status, item.code])).toEqual([['removed', 200], ['unconfirmed', 409], ['not_attempted', null]]);
  expect(result.results[1].operationId).toBeNull(); expect(result.results[2].operationId).toBeNull(); expect(removeMember).toHaveBeenCalledTimes(2);
});
test('changed target authorization revision alone is tolerated, original actor context is frozen', async () => {
  read.mockImplementation(async () => ({ ...source, target: { ...source.target, revision: String(read.mock.calls.length) } }));
  expect((await service.remove(userId, intent, user, 'Bearer original')).results[0].status).toBe('removed');
  read.mockReset().mockResolvedValueOnce(source).mockResolvedValue({ ...source, context: { ...source.context, revision: '2' } });
  await expect(service.remove(userId, intent, user, 'Bearer original')).rejects.toMatchObject({ status: 401 });
});
test('retained old incarnation recovers without GroupMutator replay', async () => {
  intent.memberships = [intent.memberships[0]]; const operationId = randomUUID(); const stored = { id: randomUUID(), group_id: intent.memberships[0].groupId,
    before_group_revision: intent.memberships[0].groupRevision, operation_id: operationId };
  const actual = query.getMockImplementation(); query.mockImplementation((sql, values) => sql.startsWith('SELECT * FROM identity_company_offboarding_group_receipts') ? { rows: [stored] } : actual(sql, values));
  const result = await service.remove(userId, intent, user, 'Bearer original');
  expect(result.results[0]).toMatchObject({ status: 'already_removed', code: 200, operationId }); expect(removeMember).not.toHaveBeenCalled();
  expect(query.mock.calls.some(([sql]) => sql.startsWith('INSERT INTO identity_company_offboarding_group_receipts'))).toBe(false);
});
test('original source loss after child uncertainty withholds the result', async () => {
  removeMember.mockImplementation(async () => { read.mockRejectedValue(Object.assign(new Error('Original bearer withdrawn'), { status: 401 })); throw new Error('Unknown child response'); });
  await expect(service.remove(userId, intent, user, 'Bearer original')).rejects.toMatchObject({ status: 401 }); expect(removeMember).toHaveBeenCalledTimes(1);
});
test('empty preview keeps exact versioned DTO and only read permission', async () => {
  const result = await service.preview(userId, { workflowId: intent.workflowId }, user, 'Bearer original');
  expect(Object.keys(result)).toEqual(['schemaVersion', 'companyOffboardingGroupsProtocol', 'actorUserId', 'tenantId', 'workflowId', 'userId', 'target', 'groups', 'total', 'page', 'limit']);
  expect(result).toMatchObject({ companyOffboardingGroupsProtocol: 1, target: { enabled: false, eligibilityRevision: intent.eligibilityRevision }, groups: [], total: 0, page: 1, limit: 25 });
  expect(requireDirectoryPermissions.mock.calls.every(call => JSON.stringify(call[2]) === JSON.stringify(['groups.read']))).toBe(true);
});
