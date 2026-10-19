'use strict';

const { randomUUID } = require('node:crypto'); const { OuMutator } = require('../OuMutator'); const { DirectoryReader } = require('../DirectoryReader');
const { getIdentityPermissions } = require('../middleware/identityAccess');
const unitId = randomUUID(); const userId = randomUUID(); let database; let revalidate; let mutator;
beforeEach(() => { database = { isAvailable: jest.fn(() => true), transaction: jest.fn() }; revalidate = jest.fn(); mutator = new OuMutator(database, { revalidate }); });
test.each([{}, [], { userId: 'alias' }, { userId, tenantId: randomUUID() }, { userId, id: randomUUID() }, { userId, enabled: true }])('membership input cannot invent scope, identity or record authority: %j', async body => {
  await expect(mutator.addMember(unitId, body, '"unknown"', {}, 'Bearer original')).rejects.toMatchObject({ status: 400 }); expect(revalidate).not.toHaveBeenCalled();
});
test.each(['alias', '', undefined, null])('removal requires a canonical membership incarnation, not a guessed user name: %s', async membershipId => {
  await expect(mutator.removeMember(unitId, membershipId, '"unknown"', {}, 'Bearer original')).rejects.toMatchObject({ status: 400 }); expect(revalidate).not.toHaveBeenCalled();
});
test.each([{ tenantId: randomUUID() }, { page: '0' }, { limit: '101' }, { page: 1 }, { search: 'employee' }])('unapproved list selectors do not start directory authority or SQL: %j', async query => {
  await expect(new DirectoryReader(database, { revalidate }).ouMembers(unitId, query, {}, 'Bearer original')).rejects.toMatchObject({ status: 400 }); expect(revalidate).not.toHaveBeenCalled(); expect(database.transaction).not.toHaveBeenCalled();
});
test('OU management gains its precise membership duty without inheriting user-profile, user-lifecycle or license rights', () => {
  const permissions = getIdentityPermissions({ actor_type: 'user', roles: ['ou-administrator'] }); expect(permissions).toContain('ous.members.manage');
  for (const denied of ['users.read', 'users.status.manage', 'users.delete', 'licenses.sources.manage']) expect(permissions).not.toContain(denied);
  expect(getIdentityPermissions({ actor_type: 'application', permissions: ['ous.members.manage'] })).toEqual([]);
});
