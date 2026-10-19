'use strict';

const { randomUUID } = require('crypto');
jest.mock('../CompanyLicenseAuthority', () => ({ CompanyLicenseAuthority: jest.fn() }));
jest.mock('../DirectoryAuthority', () => ({ requireDirectoryPermissions: jest.fn(async () => {}) }));
jest.mock('../UserMutator', () => ({ UserMutator: jest.fn() }));
const { CompanyLicenseAuthority } = require('../CompanyLicenseAuthority');
const { requireDirectoryPermissions } = require('../DirectoryAuthority');
const { UserMutator } = require('../UserMutator');
const { CompanyOffboarding } = require('../CompanyOffboarding');
const { requireIdentityAccess } = require('../middleware/identityAccess');
let user; let body; let target; let source; let row; let query; let read; let update; let bridge; let database;
beforeEach(() => {
  jest.clearAllMocks(); target = randomUUID(); body = { workflowId: randomUUID(), expectedRevision: '9007199254740993', confirm: true };
  user = { sub: 'current-owner', identity_authorization: { userId: randomUUID() } };
  source = { issuer: 'https://company.test', subject: user.sub, actorUserId: user.identity_authorization.userId,
    context: user.identity_authorization, tenant: { id: randomUUID(), version: '1', generation: '1' }, validUntil: 9999999999,
    target: { id: target, enabled: true, deleted: false, eligibilityRevision: '123' } };
  row = { tenant_id: source.tenant.id, workflow_id: body.workflowId, user_id: target, actor_user_id: source.actorUserId,
    operation_id: randomUUID(), action: 'disabled', before_revision: body.expectedRevision, expected_revision: body.expectedRevision,
    after_revision: '9007199254741000', before_eligibility_revision: '123', after_eligibility_revision: '999', created_at: new Date() };
  read = jest.fn(async () => source); CompanyLicenseAuthority.mockImplementation(() => ({ read }));
  update = jest.fn(async () => {}); UserMutator.mockImplementation(() => ({ update }));
  query = jest.fn(async sql => {
    if (sql.startsWith('SELECT * FROM identity_company_offboarding_receipts')) return { rows: [] };
    if (sql.startsWith('SELECT record_revision')) return { rows: [{ record_revision: body.expectedRevision, eligibility_revision: '123', enabled: true }] };
    if (sql.startsWith('SELECT identity_subject_link_role_state')) return { rows: [{ state: {} }] };
    if (sql.startsWith('INSERT INTO identity_company_offboarding_receipts')) return { rows: [row] };
    return { rows: [] };
  });
  database = { isAvailable: () => true, transaction: jest.fn(async (operation, options) => {
    const client = { query }; const result = await operation(client); await options.beforeCommit(client); return result;
  }) };
  bridge = new CompanyOffboarding(database, { issuer: source.issuer, revalidate: async () => source.tenant });
});
test.each([{}, [], null, { workflowId: 'alias', expectedRevision: '1', confirm: true },
  { workflowId: randomUUID(), expectedRevision: 1, confirm: true }, { workflowId: randomUUID(), expectedRevision: '0', confirm: true },
  { workflowId: randomUUID(), expectedRevision: '9223372036854775808', confirm: true },
  { workflowId: randomUUID(), expectedRevision: '01', confirm: true }, { workflowId: randomUUID(), expectedRevision: '1', confirm: false }])('rejects malformed commands before authority or storage: %j', async input => {
  await expect(bridge.receive(target, input, user, 'Bearer original')).rejects.toMatchObject({ status: 400 }); expect(read).not.toHaveBeenCalled(); expect(query).not.toHaveBeenCalled();
});
test('rejects selectors, noncanonical workflow UUIDs and canonical self targets before storage', async () => {
  for (const extra of ['tenantId', 'roles', 'userId']) await expect(bridge.receive(target, { ...body, [extra]: target }, user, 'Bearer original')).rejects.toMatchObject({ status: 400 });
  await expect(bridge.receive(target, { ...body, workflowId: body.workflowId.toUpperCase() }, user, 'Bearer original')).rejects.toMatchObject({ status: 400 });
  await expect(bridge.receive(user.identity_authorization.userId.toUpperCase(), body, user, 'Bearer original')).rejects.toMatchObject({ status: 403 }); expect(read).not.toHaveBeenCalled();
});
test('wraps the actual UserMutator with one fixed server UUID and revalidates the original bearer through physical commit', async () => {
  const result = await bridge.receive(target, body, user, 'Bearer original');
  expect(Object.keys(result)).toEqual(['schemaVersion', 'workflowId', 'tenantId', 'userId', 'actorUserId', 'operationId', 'action', 'beforeRevision', 'afterRevision', 'beforeEligibilityRevision', 'afterEligibilityRevision', 'createdAt', 'deliveryStatus']);
  expect(result).toMatchObject({ beforeRevision: body.expectedRevision, afterEligibilityRevision: '999', deliveryStatus: 'pending' });
  expect(update).toHaveBeenCalledWith(target, { enabled: false }, `"user-${target}-${body.expectedRevision}"`, user, 'Bearer original');
  const settings = UserMutator.mock.calls[0][1]; expect(settings.newOperationId()).toBe(settings.newOperationId()); expect(settings.newOperationId()).toMatch(/^[a-f0-9-]{36}$/);
  expect(requireDirectoryPermissions).toHaveBeenCalledWith(expect.anything(), user, ['users.update', 'users.status.manage']);
  expect(read.mock.calls.every(call => call[0] === user && call[1] === 'Bearer original' && call[2].userId === target)).toBe(true);
});
test('lost responses return the immutable original actor receipt without reapplying or requiring the original operator', async () => {
  row.actor_user_id = randomUUID();
  query.mockImplementation(async sql => ({ rows: sql.startsWith('SELECT * FROM identity_company_offboarding_receipts') ? [row]
    : sql.startsWith('SELECT identity_subject_link_role_state') ? [{ state: {} }] : [] }));
  const first = await bridge.receive(target, body, user, 'Bearer refreshed'); const second = await bridge.receive(target, body, user, 'Bearer refreshed-again');
  expect(second).toEqual(first); expect(first.actorUserId).toBe(row.actor_user_id); expect(update).not.toHaveBeenCalled(); expect(query.mock.calls.some(([sql]) => sql.startsWith('INSERT'))).toBe(false);
});
test.each(['user_id', 'expected_revision'])('same tenant workflow key cannot change %s', async field => {
  row[field] = field === 'user_id' ? randomUUID() : '2';
  query.mockImplementation(async sql => ({ rows: sql.startsWith('SELECT * FROM identity_company_offboarding_receipts') ? [row] : [] }));
  await expect(bridge.receive(target, body, user, 'Bearer original')).rejects.toMatchObject({ status: 409 }); expect(update).not.toHaveBeenCalled();
});
test('stale record revision fails before mutation even when authorization and eligibility revisions differ', async () => {
  body.expectedRevision = '5';
  query.mockImplementation(async sql => ({ rows: sql.startsWith('SELECT record_revision') ? [{ record_revision: '6', eligibility_revision: '5', enabled: true }] : [] }));
  update.mockClear(); await expect(bridge.receive(target, body, user, 'Bearer original')).rejects.toMatchObject({ status: 412 }); expect(update).not.toHaveBeenCalled();
});
test('already disabled stores an observation without invoking UserMutator', async () => {
  const originalQuery = query.getMockImplementation(); query.mockImplementation(async sql => sql.startsWith('SELECT record_revision')
    ? { rows: [{ record_revision: body.expectedRevision, eligibility_revision: '123', enabled: false }] } : originalQuery(sql));
  row.operation_id = null; row.action = 'already_disabled'; row.after_revision = row.before_revision; row.after_eligibility_revision = '123';
  expect(await bridge.receive(target, body, user, 'Bearer original')).toMatchObject({ operationId: null, action: 'already_disabled' }); expect(update).not.toHaveBeenCalled();
});
test('foreign source denial occurs before workflow reads or mutation', async () => {
  read.mockRejectedValue(Object.assign(new Error('Foreign target'), { status: 404 })); await expect(bridge.receive(target, body, user, 'Bearer original')).rejects.toMatchObject({ status: 404 }); expect(query).not.toHaveBeenCalled();
});
test('the exact routing path admits roleless human owners to the live bridge but no workloads or alternate methods', () => {
  const response = { status: jest.fn().mockReturnThis(), json: jest.fn() };
  for (const [method, path, actor_type, allowed] of [['POST', `/users/${target}/company-offboarding`, 'user', true],
    ['GET', `/users/${target}/company-offboarding`, 'user', false], ['POST', `/users/${target}/company-offboarding/other`, 'user', false],
    ['POST', `/users/${target}/company-offboarding`, 'application', false]]) {
    const next = jest.fn(); requireIdentityAccess({ method, path, user: { sub: 'owner', actor_type }, body }, response, next); expect(next).toHaveBeenCalledTimes(allowed ? 1 : 0);
  }
});
