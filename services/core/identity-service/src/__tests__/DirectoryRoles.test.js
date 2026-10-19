'use strict';

const { randomUUID } = require('crypto');
jest.mock('../AuthorityCheckpoint', () => ({ ...jest.requireActual('../AuthorityCheckpoint'), beginAuthorityCheckpoint: jest.fn(async () => async () => {}) }));
jest.mock('../RoleState', () => ({ readRoleState: jest.fn(async () => ({ roles: ['role-administrator'], rolesRevision: 'a'.repeat(64), authentication: { required: false, maxAgeSeconds: 86400 } })) }));
const { DirectoryRoles } = require('../DirectoryRoles');
const { argumentsForBootstrap } = require('../../scripts/bootstrap-role');
const target = randomUUID();
const tenant = randomUUID();
const actor = { iss: 'https://issuer.test', sub: 'operator', actor_type: 'user', roles: ['role-administrator'],
  identity_authorization: { userId: randomUUID(), revision: '1', linkRevision: '2', rolesRevision: 'a'.repeat(64) } };
const body = { role: 'license-manager', durationSeconds: 3600, reason: 'Reviewed license delegation' };
let database; let store;
beforeEach(() => {
  database = { query: jest.fn(async sql => {
    if (sql.includes('pg_catalog.pg_trigger')) return { rows: ['identity_role_assignments', 'identity_pim_eligibilities', 'identity_pim_requests', 'identity_role_review_leases'].map(relname => ({ relname })) };
    if (sql.includes('identity_authority_actor_home')) return { rows: [{ tenant_id: tenant }] };
    if (sql.includes('FROM identity_tenants')) return { rows: [{ id: tenant }] };
    if (sql.includes('FROM users WHERE id=ANY')) return { rows: [target, actor.identity_authorization.userId].map(id => ({ id, enabled: true, authorization_revision: '1' })) };
    if (sql.includes('COUNT(*)')) return { rows: [{ count: 0 }] };
    if (sql.includes('INSERT INTO')) return { rows: [{ id: randomUUID(), user_id: target, role: body.role, reason: body.reason, created_at: new Date(), expires_at: new Date(Date.now() + 3600000), status: 'active' }] };
    return { rows: [{ id: target }] };
  }), transaction: jest.fn() };
  database.transaction.mockImplementation(operation => operation(database)); store = new DirectoryRoles(database, { revalidate: jest.fn(async () => {}) });
});
test('a bounded grant writes the verified canonical actor and only catalog fields', async () => {
  expect(await store.grant(target, body, actor)).toMatchObject({ userId: target, role: body.role, status: 'active' });
  expect(database.transaction).toHaveBeenCalledWith(expect.any(Function), { actor: JSON.stringify({ issuer: actor.iss, subject: actor.sub, userId: actor.identity_authorization.userId }) });
  expect(database.query).toHaveBeenCalledWith(expect.stringContaining("identity_tenant_id('user',id)=$2"), [[target, actor.identity_authorization.userId].sort(), tenant]);
  expect(database.query).toHaveBeenCalledWith(expect.stringContaining('INSERT INTO'), [target, body.role, body.reason, 3600]);
});
test.each([
  { role: 'made-up-admin' }, { durationSeconds: 0 }, { durationSeconds: 59 }, { durationSeconds: 28801 }, { durationSeconds: '3600' },
  { expiresAt: null }, { permissions: ['users.delete'] }, { reason: 'short' }, { reason: 'control\ncharacters' }, { role: '__proto__' },
])('invalid or unbounded grants never reach storage: %j', async patch => {
  await expect(store.grant(target, { ...body, ...patch }, actor)).rejects.toMatchObject({ status: 400 }); expect(database.transaction).not.toHaveBeenCalled();
});
test('self-escalation through another subject or UUID casing is denied before storage', async () => {
  await expect(store.grant(actor.identity_authorization.userId.toUpperCase(), body, { ...actor, sub: 'another-linked-alias' })).rejects.toMatchObject({ status: 403 });
  expect(database.transaction).not.toHaveBeenCalled();
});
test.each(['admin', 'role-administrator', 'pim-administrator', 'pim-approver', 'authentication-policy-administrator','license-provider-administrator','license-fulfillment-operator'])('a delegated role administrator cannot grant protected %s', async role => {
  await expect(store.grant(target, { ...body, role }, actor)).rejects.toMatchObject({ status: 403 }); expect(database.transaction).not.toHaveBeenCalled();
});
test('workloads and legacy unbound administrators cannot administer human roles', async () => {
  for (const user of [{ ...actor, actor_type: 'application' }, { ...actor, roles: ['admin'], identity_authorization: undefined }]) {
    await expect(store.grant(target, body, user)).rejects.toMatchObject({ status: 403 });
  }
  expect(database.transaction).not.toHaveBeenCalled();
});
test('source failures do not create a successful in-memory grant', async () => {
  database.transaction.mockRejectedValue(new Error('offline'));
  await expect(store.grant(target, body, actor)).rejects.toThrow('offline'); await expect(store.list(target)).rejects.toThrow('offline');
});
test('full active-assignment state cannot be extended', async () => {
  const original = database.query.getMockImplementation(); database.query.mockImplementation((sql, values) => sql.includes('COUNT(*)') ? { rows: [{ count: 100 }] } : original(sql, values));
  await expect(store.grant(target, body, actor)).rejects.toMatchObject({ status: 409 });
  expect(database.query.mock.calls.some(([sql]) => sql.includes('INSERT INTO'))).toBe(false);
});
test('a role-manager grant does not permit revoking protected roles', async () => {
  const id = randomUUID(); const original = database.query.getMockImplementation(); database.query.mockImplementation((sql, values) => sql.includes('FROM identity_role_assignments WHERE user_id') ? { rows: [{ id, user_id: target, role: 'admin' }] } : original(sql, values));
  await expect(store.revoke(target, id, actor)).rejects.toMatchObject({ status: 403 });
  expect(database.query.mock.calls.some(([sql]) => sql.includes('UPDATE identity_role_assignments'))).toBe(false);
});
test('offline recovery requires explicit canonical ID, catalog role, lifetime and reason', () => {
  expect(argumentsForBootstrap([target, 'admin', '--permanent', body.reason])).toEqual({ userId: target, role: 'admin', duration: null, reason: body.reason });
  for (const args of [[target, 'user', '--permanent', body.reason], ['guessed-login', 'admin', '--permanent', body.reason], [target, 'admin', '999999', body.reason], [target, 'admin', '--permanent', 'short']]) {
    expect(() => argumentsForBootstrap(args)).toThrow();
  }
});
