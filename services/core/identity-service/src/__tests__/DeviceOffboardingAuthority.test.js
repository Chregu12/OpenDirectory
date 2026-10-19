'use strict';

const { randomUUID } = require('node:crypto');
jest.mock('../DeviceInventoryAuthority', () => ({ DeviceInventoryAuthority: jest.fn() }));
const { DeviceInventoryAuthority } = require('../DeviceInventoryAuthority');
const { DeviceOffboardingAuthority } = require('../DeviceOffboardingAuthority');
const { INVENTORY_PERMISSIONS } = require('../../../../../packages/device-inventory-contract');
let user; let body; let source; let parent; let read; let query; let database; let authority;
beforeEach(() => {
  jest.clearAllMocks(); const actorUserId = randomUUID(); body = { workflowId: randomUUID(), userId: randomUUID() };
  user = { identity_authorization: { userId: actorUserId, revision: '1', linkRevision: '1', rolesRevision: 'a'.repeat(64) } };
  source = { schemaVersion: 1, issuer: 'https://device-offboarding.test', subject: 'original-owner', tokenId: randomUUID(), expiresAt: 9999999999,
    context: user.identity_authorization, tenant: { id: randomUUID(), version: '1', generation: '1' }, actorUserId, permissions: [...INVENTORY_PERMISSIONS],
    validUntil: 9999999999, target: { id: body.userId, enabled: false, revision: '2' } };
  parent = { workflow_id: body.workflowId, tenant_id: source.tenant.id, user_id: body.userId, action: 'disabled', operation_id: randomUUID(),
    after_revision: '9007199254740993', after_eligibility_revision: '9223372036854775807', current_eligibility_revision: '9223372036854775807', created_at: new Date('2026-10-19T12:00:00Z') };
  read = jest.fn(async () => structuredClone(source)); DeviceInventoryAuthority.mockImplementation(() => ({ read }));
  query = jest.fn(async sql => ({ rows: sql.startsWith('SELECT parent.*') ? [parent] : [] }));
  database = { transaction: jest.fn(async (operation, options = {}) => { const client = { query }; const result = await operation(client); await options.beforeCommit?.(client); return result; }) };
  authority = new DeviceOffboardingAuthority(database, { issuer: source.issuer });
});
test('the actual existing inventory source gains only a validated negative account checkpoint, not a new permission or token', async () => {
  const result = await authority.read(user, 'Bearer original', body);
  expect(Object.keys(result)).toHaveLength(13); expect(result.permissions).toEqual(INVENTORY_PERMISSIONS); expect(result.tokenId).toBe(source.tokenId);
  expect(result.target).toEqual({ id: body.userId, enabled: false, eligibilityRevision: parent.after_eligibility_revision });
  expect(result.parent).toEqual({ workflowId: body.workflowId, tenantId: source.tenant.id, userId: body.userId, action: 'disabled', operationId: parent.operation_id,
    afterRevision: '9007199254740993', afterEligibilityRevision: '9223372036854775807', createdAt: '2026-10-19T12:00:00.000Z', deliveryStatus: 'pending' });
  expect(read).toHaveBeenCalledTimes(4); expect(read).toHaveBeenCalledWith(user, 'Bearer original', { userId: body.userId });
  expect(database.transaction.mock.calls.every(call => call[1].readOnly)).toBe(true);
  expect(query).toHaveBeenCalledWith('SELECT identity_company_offboarding_validate($1,$2,$3)', [source.tenant.id, body.workflowId, body.userId]);
});
test.each([null, [], {}, { workflowId: randomUUID() }, { workflowId: '*', userId: randomUUID() },
  { workflowId: randomUUID(), userId: 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA' }, { workflowId: randomUUID(), userId: randomUUID(), tenantId: randomUUID() }])('invalid or caller-owned source selectors are rejected before authority %j', async value => {
  await expect(authority.read(user, 'Bearer original', value)).rejects.toMatchObject({ status: 400 }); expect(read).not.toHaveBeenCalled();
});
test('self offboarding never acquires an inventory source', async () => {
  await expect(authority.read(user, 'Bearer original', { ...body, userId: source.actorUserId })).rejects.toMatchObject({ status: 403 }); expect(read).not.toHaveBeenCalled();
});
test.each([401, 403, 404, 428, 503])('original canonical inventory denial %i is not replaced by claimed roles or app permissions', async status => {
  read.mockRejectedValue(Object.assign(new Error('Original source rejected'), { status }));
  await expect(authority.read({ ...user, roles: ['admin'], permissions: ['company.apps.assign'] }, 'Bearer original', body)).rejects.toMatchObject({ status }); expect(query).not.toHaveBeenCalled();
});
test('enabled or later reactivated targets cannot borrow an old negative parent', async () => {
  source.target.enabled = true; await expect(authority.read(user, 'Bearer original', body)).rejects.toMatchObject({ status: 409 }); expect(query).not.toHaveBeenCalled();
});
test.each([null, { current_eligibility_revision: '2' }])('missing or changed negative account evidence cannot be used %j', async change => {
  query.mockImplementation(async sql => ({ rows: sql.startsWith('SELECT parent.*') ? change === null ? [] : [{ ...parent, ...change }] : [] }));
  await expect(authority.read(user, 'Bearer original', body)).rejects.toMatchObject({ status: 409 });
});
test('already-disabled evidence has no invented disable operation', async () => {
  parent.action = 'already_disabled'; parent.operation_id = null;
  expect((await authority.read(user, 'Bearer original', body)).parent).toMatchObject({ action: 'already_disabled', operationId: null });
});
test('legitimate target authorization revision changes from role cleanup do not change negative eligibility', async () => {
  let counter = 0; read.mockImplementation(async () => ({ ...structuredClone(source), target: { ...source.target, revision: String(++counter) } }));
  const result = await authority.read(user, 'Bearer original', body); expect(result.target.eligibilityRevision).toBe(parent.after_eligibility_revision); expect(result.target).not.toHaveProperty('revision');
});
test.each(['issuer', 'subject', 'tokenId', 'expiresAt', 'validUntil', 'actorUserId', 'permissions', 'context', 'tenant'])('original actor source %s cannot drift between checkpoints', async field => {
  let calls = 0; read.mockImplementation(async () => {
    const next = structuredClone(source);
    if (++calls > 1) next[field] = field === 'context' ? { ...source.context, revision: '2' } : field === 'tenant' ? { ...source.tenant, generation: '2' }
      : field === 'permissions' ? ['admin'] : typeof source[field] === 'number' ? source[field] + 1 : 'changed';
    return next;
  });
  await expect(authority.read(user, 'Bearer original', body)).rejects.toMatchObject({ status: 401 });
});
test('a missing retained receiving or outbox proof is unavailable, never a successful parent observation', async () => {
  query.mockImplementation(async sql => { if (sql.includes('offboarding_validate')) throw Object.assign(new Error('Missing retained outbox'), { code: '23514' }); return { rows: [parent] }; });
  await expect(authority.read(user, 'Bearer original', body)).rejects.toMatchObject({ status: 503 });
});
test('a new negative generation after the read-only snapshot withholds the final source', async () => {
  let calls = 0; query.mockImplementation(async sql => ({ rows: sql.startsWith('SELECT parent.*') ? [{ ...parent, current_eligibility_revision: ++calls > 2 ? '2' : parent.after_eligibility_revision }] : [] }));
  await expect(authority.read(user, 'Bearer original', body)).rejects.toMatchObject({ status: 409 });
});
