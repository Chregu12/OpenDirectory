const { commandBody } = require('../OrganizationDelegations');
const { getIdentityPermissions } = require('../middleware/identityAccess');
const userId = '11111111-1111-4111-8111-111111111111';
test('accepts only a bounded explicit delegation with a reason and no role, tenant or arbitrary permissions', () => {
  expect(commandBody({ userId, durationSeconds: 3600, reason: '  Reviewed profile delegation  ' }, true)).toEqual({ userId, durationSeconds: 3600, reason: 'Reviewed profile delegation' });
  expect(commandBody({ reason: 'Reviewed profile revocation' }, false)).toEqual({ reason: 'Reviewed profile revocation' });
});
test.each([null, [], {}, { userId, durationSeconds: 59, reason: 'Reviewed delegation' }, { userId, durationSeconds: 28801, reason: 'Reviewed delegation' },
  { userId, durationSeconds: 300.1, reason: 'Reviewed delegation' }, { userId: 'not-a-user', durationSeconds: 300, reason: 'Reviewed delegation' },
  { userId, durationSeconds: 300, reason: 'short' }, { userId, durationSeconds: 300, reason: 'Reviewed\n delegation' },
  { userId, durationSeconds: 300, reason: 'Reviewed delegation', tenantId: userId }, { userId, durationSeconds: 300, reason: 'Reviewed delegation', role: 'admin' }])('rejects unsafe delegation command %#', body => {
  expect(() => commandBody(body, true)).toThrow('invalid_organization_delegation');
});
test('only existing administration can manage delegations, ordinary or scoped users do not inherit it', () => {
  expect(getIdentityPermissions({ roles: ['admin'] })).toContain('organization.delegations.manage');
  for (const roles of [['user'], ['directory-reader'], ['user-administrator'], ['role-administrator'], ['license-administrator']]) expect(getIdentityPermissions({ roles })).not.toContain('organization.delegations.manage');
});
