'use strict';

const { randomUUID } = require('node:crypto');
jest.mock('../CompanyOffboardingAccessAuthority', () => ({ CompanyOffboardingAccessAuthority: jest.fn() }));
jest.mock('../DirectoryRoles', () => ({ DirectoryRoles: jest.fn() }));
jest.mock('../PrivilegedActivation', () => ({ PrivilegedActivation: jest.fn() }));
const { CompanyOffboardingAccessAuthority } = require('../CompanyOffboardingAccessAuthority');
const { DirectoryRoles } = require('../DirectoryRoles');
const { PrivilegedActivation } = require('../PrivilegedActivation');
const { CompanyOffboardingAccess } = require('../CompanyOffboardingAccess');
let user; let source; let userId; let intent; let read; let query; let revokeRole; let revokeEligibility; let database; let service;
beforeEach(() => {
  jest.clearAllMocks(); userId = randomUUID();
  user = { sub: 'canonical-operator', jti: randomUUID(), exp: 9999999999, auth_time: 9999999700, actor_type: 'user', identity_authorization: { userId: randomUUID(), revision: '1', linkRevision: '1', rolesRevision: 'a'.repeat(64) } };
  source = { issuer: 'https://cleanup.test', subject: user.sub, actorUserId: user.identity_authorization.userId, context: user.identity_authorization,
    tenant: { id: randomUUID(), version: '1', generation: '1' }, tokenId: user.jti, expiresAt: user.exp, validUntil: 9999999999,
    roles: ['role-administrator'], permissions: ['identities.roles.read', 'identities.roles.manage'] };
  intent = { workflowId: randomUUID(), eligibilityRevision: '9007199254740993', kind: 'role', reason: 'Explicit captured role access cleanup', confirm: true,
    items: Array.from({ length: 3 }, () => ({ id: randomUUID(), version: 'a'.repeat(64) })) };
  read = jest.fn(async () => source); CompanyOffboardingAccessAuthority.mockImplementation(() => ({ read }));
  query = jest.fn(async (sql, values) => {
    if (sql.startsWith('SELECT account.id')) return { rows: [{ id: userId, enabled: false, eligibility_revision: intent.eligibilityRevision, after_eligibility_revision: intent.eligibilityRevision }] };
    if (sql.startsWith('SELECT graph,identity_authority_hash')) return { rows: [{ graph: { grant: { id: values[1], user_id: userId, role: 'directory-reader', revoked_at: null } }, version: 'a'.repeat(64) }] };
    if (sql.startsWith('SELECT identity_subject_link_role_state')) return { rows: [{ state: {} }] };
    if (sql.startsWith('SELECT count(*)')) return { rows: [{ count: '0' }] };
    return { rows: [] };
  });
  database = { isAvailable: () => true, transaction: jest.fn(async (operation, options = {}) => {
    const client = { query }; const result = await operation(client); await options.beforeCommit?.(client); return result;
  }) };
  revokeRole = jest.fn(async () => {}); revokeEligibility = jest.fn(async () => {});
  function childOperation(child) { return async (...parameters) => {
    await child.transaction(async client => { await revokeRole(...parameters); await client.query('SELECT identity_authority_command_checkpoint($1::uuid,$2::jsonb,$3::jsonb,$4::bigint) AS checkpoint', [randomUUID(), '{}', '{}', '9999999999']); });
  }; }
  DirectoryRoles.mockImplementation(child => ({ revoke: childOperation(child) }));
  PrivilegedActivation.mockImplementation(child => ({ revokeEligibility: async (...parameters) => { await revokeEligibility(...parameters); await child.transaction(client => client.query('SELECT identity_authority_command_checkpoint($1::uuid,$2::jsonb,$3::jsonb,$4::bigint) AS checkpoint', [randomUUID()])); } }));
  service = new CompanyOffboardingAccess(database);
});
test.each([null, [], {}, { workflowId: randomUUID() }, { workflowId: randomUUID(), kind: 'other' }, { workflowId: randomUUID(), kind: 'role', page: 1 }, { workflowId: randomUUID(), kind: 'role', limit: '24' }])('invalid selectors rejected before source: %j', async selectors => {
  await expect(service.preview(userId, selectors, user, 'Bearer original')).rejects.toMatchObject({ status: 400 }); expect(read).not.toHaveBeenCalled();
});
test.each(['tenantId', 'actorUserId', 'permissions', 'checkpointId', 'correlationId', 'tokenId'])('caller cannot supply %s', async field => {
  await expect(service.revoke(userId, { ...intent, [field]: randomUUID() }, user, 'Bearer original')).rejects.toMatchObject({ status: 400 }); expect(read).not.toHaveBeenCalled();
});
test('capabilities exposes actual subset without reading grants', async () => {
  const result = await service.capabilities(userId, { workflowId: intent.workflowId }, user, 'Bearer original');
  expect(Object.keys(result)).toEqual(['schemaVersion', 'companyOffboardingAccessProtocol', 'actorUserId', 'tenantId', 'workflowId', 'userId', 'target', 'permissions', 'supportedKinds']);
  expect(result.supportedKinds).toEqual(['role']); expect(result.permissions).toEqual(source.permissions); expect(result.target.eligibilityRevision).toBe(intent.eligibilityRevision);
  expect(query.mock.calls.some(([sql]) => sql.includes('FROM identity_role_assignments'))).toBe(false);
});
test('self and missing original parent fail before any mutation', async () => {
  await expect(service.preview(user.identity_authorization.userId, { workflowId: intent.workflowId, kind: 'role' }, user, 'Bearer original')).rejects.toMatchObject({ status: 403 });
  const actual = query.getMockImplementation(); query.mockImplementation((sql, values) => sql.startsWith('SELECT account.id') ? { rows: [] } : actual(sql, values));
  await expect(service.revoke(userId, intent, user, 'Bearer original')).rejects.toMatchObject({ status: 409 }); expect(revokeRole).not.toHaveBeenCalled();
});
test('roleless company owner cannot read or revoke through this independent source', async () => {
  source.roles = []; source.permissions = [];
  await expect(service.capabilities(userId, { workflowId: intent.workflowId }, user, 'Bearer original')).rejects.toMatchObject({ status: 403 });
  await expect(service.revoke(userId, intent, user, 'Bearer original')).rejects.toMatchObject({ status: 403 }); expect(revokeRole).not.toHaveBeenCalled();
  expect(query.mock.calls.some(([sql]) => sql.startsWith('SELECT account.id'))).toBe(false);
});
test('whole manifest readonly preflight precedes every child; finish is before actual kernel checkpoint', async () => {
  const result = await service.revoke(userId, intent, user, 'Bearer original'); expect(result.results.map(item => item.status)).toEqual(['revoked', 'revoked', 'revoked']);
  expect(revokeRole.mock.calls[0]).toEqual([userId, intent.items[0].id, user, 'Bearer original']); expect(new Set(result.results.map(item => item.checkpointId)).size).toBe(3);
  const firstBegin = query.mock.calls.findIndex(([sql]) => sql.startsWith('SELECT identity_company_offboarding_access_begin'));
  expect(query.mock.calls.slice(0, firstBegin).filter(([sql]) => sql.startsWith('SELECT graph,identity_authority_hash')).length).toBe(4);
  const finish = query.mock.calls.findIndex(([sql]) => sql.startsWith('SELECT identity_company_offboarding_access_finish'));
  const checkpoint = query.mock.calls.findIndex(([sql]) => sql.startsWith('SELECT identity_authority_command_checkpoint(')); expect(finish).toBeLessThan(checkpoint);
  expect(database.transaction.mock.calls[0][1].readOnly).toBe(true);
});
test('later uncertain canonical child stops remainder without refreshing manifest or retry', async () => {
  revokeRole.mockResolvedValueOnce({}).mockRejectedValueOnce(Object.assign(new Error('Conflict'), { status: 412 }));
  const result = await service.revoke(userId, intent, user, 'Bearer original');
  expect(result.results.map(item => [item.status, item.code])).toEqual([['revoked', 200], ['unconfirmed', 412], ['not_attempted', null]]); expect(revokeRole).toHaveBeenCalledTimes(2);
  expect(result.results[1].checkpointId).toBeNull();
});
test('retained matching receipt recovers its original checkpoint without touching a newer grant', async () => {
  const stored = { id: randomUUID(), version: 'a'.repeat(64), role: 'directory-reader', checkpoint_id: randomUUID() }; const actual = query.getMockImplementation();
  query.mockImplementation((sql, values) => sql.startsWith('SELECT * FROM identity_company_offboarding_access_receipts') ? { rows: [stored] } : actual(sql, values));
  const result = await service.revoke(userId, intent, user, 'Bearer original'); expect(result.results.every(item => item.status === 'already_revoked' && item.checkpointId === stored.checkpoint_id)).toBe(true); expect(revokeRole).not.toHaveBeenCalled();
});
test('retained receipt cannot recover with refreshed or caller-invented version', async () => {
  const actual = query.getMockImplementation(); query.mockImplementation((sql, values) => sql.startsWith('SELECT * FROM identity_company_offboarding_access_receipts') ? { rows: [{ version: 'b'.repeat(64) }] } : actual(sql, values));
  await expect(service.revoke(userId, intent, user, 'Bearer original')).rejects.toMatchObject({ status: 412 }); expect(revokeRole).not.toHaveBeenCalled();
});
test('missing real child checkpoint cannot acknowledge a successful revoke', async () => {
  DirectoryRoles.mockImplementation(() => ({ revoke: async () => {} }));
  const result = await service.revoke(userId, intent, user, 'Bearer original'); expect(result.results.map(item => item.status)).toEqual(['unconfirmed', 'not_attempted', 'not_attempted']); expect(result.results[0].code).toBe(503);
});
test('canonical independent PIM child uses original revokeEligibility kernel', async () => {
  intent.kind = 'eligibility'; source.roles = ['pim-administrator']; source.permissions = ['pim.eligibilities.read', 'pim.eligibilities.manage'];
  const result = await service.revoke(userId, intent, user, 'Bearer original'); expect(result.results[0].status).toBe('revoked'); expect(revokeEligibility.mock.calls[0]).toEqual([intent.items[0].id, user, 'Bearer original']); expect(revokeRole).not.toHaveBeenCalled();
});
test('protected grant preflight and recovery both require actual canonical admin', async () => {
  const actual = query.getMockImplementation(); query.mockImplementation(async (sql, values) => {
    const result = await actual(sql, values); if (sql.startsWith('SELECT graph,identity_authority_hash')) result.rows[0].graph.grant.role = 'admin'; return result;
  });
  await expect(service.revoke(userId, intent, user, 'Bearer original')).rejects.toMatchObject({ status: 403 }); expect(revokeRole).not.toHaveBeenCalled();
});
test('original source loss after child uncertainty withholds the result', async () => {
  revokeRole.mockImplementation(async () => { read.mockRejectedValue(Object.assign(new Error('Original token revoked'), { status: 401 })); throw new Error('Unknown child response'); });
  await expect(service.revoke(userId, intent, user, 'Bearer original')).rejects.toMatchObject({ status: 401 }); expect(revokeRole).toHaveBeenCalledTimes(1);
});
