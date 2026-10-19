'use strict';

const { randomUUID } = require('node:crypto');
const { CompanyLicenses } = require('../licenses/CompanyLicenses');
const { companyLicenseContext } = require('../licenses/CompanyLicenseContext');
const { COMPANY_LICENSE_PERMISSIONS, poolEtag } = require('../../../../../packages/company-license-contract');
const actor = randomUUID(); const tenant = randomUUID(); const target = randomUUID(); const id = randomUUID(); const authorization = 'Bearer original.company';
let user; let source; let row; let database; let allocator; let authority; let store;
beforeEach(() => {
  const now = Math.floor(Date.now() / 1000); user = { actor_type: 'user', iss: 'https://company.test', sub: 'actual-owner', jti: randomUUID(), exp: now + 600, auth_time: now, identity_authorization: { userId: actor, revision: '1', linkRevision: '1', rolesRevision: 'c'.repeat(64) } };
  source = { schemaVersion: 1, issuer: user.iss, subject: user.sub, tokenId: user.jti, expiresAt: user.exp, context: user.identity_authorization, tenant: { id: tenant, version: '1', generation: '1' }, actorUserId: actor, permissions: [...COMPANY_LICENSE_PERMISSIONS], validUntil: now + 300, target: null };
  row = { id, business_tenant_id: tenant, business_revision: '1', company_valid: true, name: 'Actual pool', vendor: 'Vendor', description: '', total_seats: 1, active_seats: 0, license_type: 'per_user', created_at: new Date(), updated_at: new Date() };
  database = { query: jest.fn(async sql => ({ rows: sql.includes('AS supported') ? [{ supported: true }] : [row] })), getClient: jest.fn() };
  database.getClient.mockImplementation(async () => ({ query: database.query, release: jest.fn() }));
  allocator = { database, assign: jest.fn(), revoke: jest.fn(), transaction: jest.fn() };
  authority = { read: jest.fn(async (_bearer, _user, userId = null) => ({ ...source, target: userId ? { id: userId, revision: '1', eligibilityRevision: '1', enabled: true, deleted: false } : null })) };
  store = new CompanyLicenses(allocator, { authority });
});
const input = { userId: target, reason: 'Explicit own company allocation', confirm: true };
test('a foreign or missing pool is denied before recipient eligibility and before the existing allocator', async () => {
  database.query.mockResolvedValue({ rows: [] });
  await expect(store.assign(id, input, poolEtag({ id, revision: '1' }), user, authorization)).rejects.toMatchObject({ status: 404 });
  expect(authority.read).toHaveBeenCalledTimes(1); expect(authority.read).toHaveBeenCalledWith(authorization, user); expect(allocator.assign).not.toHaveBeenCalled(); expect(database.query.mock.calls.find(([sql]) => sql.startsWith('SELECT catalog.*'))[1]).toEqual([id, tenant]);
});
test('a stale exact version is rejected before target source lookup, reconciliation or any writable pool transaction', async () => {
  row.business_revision = '2'; await expect(store.assign(id, input, poolEtag({ id, revision: '1' }), user, authorization)).rejects.toMatchObject({ status: 412 });
  expect(authority.read).toHaveBeenCalledTimes(1); expect(allocator.assign).not.toHaveBeenCalled();
  expect(database.query.mock.calls.map(([sql]) => sql).filter(sql => sql.startsWith('BEGIN'))).toEqual(['BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY']);
});
test('PIM, review or external governance requires its own supported workflow, never a removal or made-up scope', async () => {
  database.query.mockImplementation(async sql => ({ rows: sql.includes('AS supported') ? [{ supported: false }] : [row] }));
  await expect(store.assign(id, input, poolEtag({ id, revision: '1' }), user, authorization)).rejects.toMatchObject({ status: 409 });
  expect(authority.read).toHaveBeenCalledTimes(1); expect(allocator.assign).not.toHaveBeenCalled(); expect(database.query.mock.calls.every(([sql]) => sql.startsWith('SELECT') || ['BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY', "SET LOCAL statement_timeout='5s'", 'COMMIT'].includes(sql))).toBe(true);
});
test.each([{ enabled: false, deleted: false }, { enabled: false, deleted: true }])('disabled or deleted own employees cannot cause global eligibility cleanup: %j', async negative => {
  authority.read.mockImplementation(async (_bearer, _user, userId) => ({ ...source, target: userId ? { id: target, revision: negative.deleted ? null : '2', eligibilityRevision: '2', ...negative } : null }));
  await expect(store.assign(id, input, poolEtag({ id, revision: '1' }), user, authorization)).rejects.toMatchObject({ status: 403 }); expect(allocator.assign).not.toHaveBeenCalled();
  expect(database.query.mock.calls.map(([sql]) => sql).filter(sql => sql.startsWith('BEGIN'))).toEqual(['BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY']);
});
test('a home-tenant change between pool preflight and original recipient source prevents any allocation', async () => {
  authority.read.mockResolvedValueOnce(source).mockResolvedValueOnce({ ...source, tenant: { ...source.tenant, generation: '2' }, target: { id: target, revision: '1', eligibilityRevision: '1', enabled: true, deleted: false } });
  await expect(store.assign(id, input, poolEtag({ id, revision: '1' }), user, authorization)).rejects.toMatchObject({ status: 401 }); expect(allocator.assign).not.toHaveBeenCalled();
});
test('an allocator return value without the actual transaction completion cannot become a successful company assignment', async () => {
  allocator.assign.mockResolvedValue({ id: randomUUID() });
  await expect(store.assign(id, input, poolEtag({ id, revision: '1' }), user, authorization)).rejects.toMatchObject({ status: 503 });
  expect(allocator.assign).toHaveBeenCalledTimes(1); expect(allocator.assign).toHaveBeenCalledWith(id, { assignee_type: 'user', assignee_id: target }, actor, { authorization }); expect(companyLicenseContext.getStore()).toBeUndefined();
});
test.each([{ company_valid: false }, { license_type: 'device' }, { active_seats: 2 }, { business_revision: '9223372036854775808' }])('unconfirmed or inconsistent canonical pools cannot be exposed as healthy local inventory: %j', async patch => {
  Object.assign(row, patch); await expect(store.assign(id, input, poolEtag({ id, revision: '1' }), user, authorization)).rejects.toMatchObject({ status: 503 }); expect(allocator.assign).not.toHaveBeenCalled();
});
test('invalid confirmation, body tenant selectors or version wildcards never enter live source transport', async () => {
  await expect(store.assign(id, { ...input, tenantId: tenant }, poolEtag({ id, revision: '1' }), user, authorization)).rejects.toMatchObject({ status: 400 });
  await expect(store.assign(id, input, '*', user, authorization)).rejects.toMatchObject({ status: 412 }); expect(authority.read).not.toHaveBeenCalled();
});
test('a source revoked after a successful capability storage check cannot leave active management capabilities', async () => {
  authority.read.mockResolvedValueOnce(source).mockRejectedValueOnce(Object.assign(new Error('Original revoked'), { status: 401 }));
  await expect(store.capabilities(user, authorization)).rejects.toMatchObject({ status: 401 }); expect(database.query).toHaveBeenCalledWith('SELECT license_company_receiving()');
});
