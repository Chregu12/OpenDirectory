'use strict';

const { randomUUID } = require('node:crypto');
jest.mock('../AuthorizationState', () => ({ AuthorizationState: jest.fn() }));
const { AuthorizationState } = require('../AuthorizationState');
const { CompanyOffboardingAccessAuthority } = require('../CompanyOffboardingAccessAuthority');
let user; let source; let revalidate; let database; let state; let service;
beforeEach(() => {
  jest.clearAllMocks(); const now = Math.floor(Date.now() / 1000); const userId = randomUUID();
  user = { iss: 'https://access.test', sub: 'canonical-role-operator', actor_type: 'user', roles: ['admin'], jti: randomUUID(), exp: now + 900,
    identity_authorization: { userId, revision: '9007199254740993', linkRevision: '9007199254740994', rolesRevision: 'a'.repeat(64) },
    auth_time: now, amr: ['pwd', 'otp'], mfa_authorization: { schemaVersion: 1, userId, revision: '1', authTime: now, methods: ['pwd', 'otp'] } };
  source = { active: true, context: user.identity_authorization, roles: ['role-administrator'], tenant: { id: randomUUID(), version: '1', generation: '1' }, authentication: { required: false, maxAgeSeconds: 86400 } };
  state = jest.fn(async () => source); AuthorizationState.mockImplementation(() => ({ state }));
  revalidate = jest.fn(async () => source.tenant); database = { isAvailable: () => true, transaction: async operation => operation({}) };
  service = new CompanyOffboardingAccessAuthority(database, { issuer: user.iss, revalidate });
});
test('uses actual canonical roles rather than claimed admin and has no company.apps dependency', async () => {
  const result = await service.read(user, 'Bearer original');
  expect(result.permissions).toEqual(['identities.roles.read', 'identities.roles.manage']); expect(result.roles).toEqual(['role-administrator']);
  expect(result.context.revision).toBe('9007199254740993'); expect(result.validUntil).toBe(user.auth_time + 300);
  expect(revalidate.mock.calls.every(call => call[0] === 'Bearer original' && call[1] === user)).toBe(true);
});
test.each([['role-reader', ['identities.roles.read']], ['pim-reader', ['pim.eligibilities.read']], ['pim-administrator', ['pim.eligibilities.read', 'pim.eligibilities.manage']], ['user', []]])('canonical %s receives only own four-duty subset', async (role, permissions) => {
  source.roles = [role]; expect((await service.read(user, 'Bearer original')).permissions).toEqual(permissions);
});
test('roleless company owner is not promoted to role or PIM administrator', async () => {
  source.roles = []; source.authentication = { required: true, maxAgeSeconds: 300 };
  expect((await service.read(user, 'Bearer original')).permissions).toEqual([]);
});
test.each([null, 'original', 'Bearer original secret', 'Bearer ' + 'a'.repeat(17000)])('invalid original bearer is rejected before canonical source: %j', async bearer => {
  await expect(service.read(user, bearer)).rejects.toMatchObject({ status: 403 }); expect(state).not.toHaveBeenCalled(); expect(revalidate).not.toHaveBeenCalled();
});
test.each(['workload', 'client'])('rejects %s actors without reading source', async actor => {
  user.actor_type = actor; await expect(service.read(user, 'Bearer original')).rejects.toMatchObject({ status: 403 }); expect(state).not.toHaveBeenCalled();
});
test.each(['missing', 'expired', 'unproven'])('independent fresh MFA remains mandatory for permissive role policy: %s', async scenario => {
  if (scenario === 'missing') delete user.mfa_authorization;
  if (scenario === 'expired') { user.auth_time -= 301; user.mfa_authorization.authTime -= 301; }
  if (scenario === 'unproven') user.amr = ['pwd'];
  await expect(service.read(user, 'Bearer original')).rejects.toMatchObject({ status: 428 }); expect(state).not.toHaveBeenCalled();
});
test.each(['inactive', 'context', 'tenant', 'policy'])('changed canonical %s cannot authorize access cleanup', async scenario => {
  if (scenario === 'inactive') source.active = false;
  if (scenario === 'context') source.context = { ...source.context, revision: '2' };
  if (scenario === 'tenant') revalidate.mockResolvedValue({ ...source.tenant, generation: '2' });
  if (scenario === 'policy') { source.authentication = { required: true, maxAgeSeconds: 300 }; user.auth_time -= 301; user.mfa_authorization.authTime -= 301; }
  await expect(service.read(user, 'Bearer original')).rejects.toMatchObject({ status: scenario === 'policy' ? 428 : 401 });
});
test('final independent original source loss is not replaced with a newly minted token', async () => {
  revalidate.mockResolvedValueOnce(source.tenant).mockRejectedValueOnce(Object.assign(new Error('Revoked bearer'), { status: 401 }));
  await expect(service.read(user, 'Bearer original')).rejects.toMatchObject({ status: 401 }); expect(revalidate).toHaveBeenCalledTimes(2);
});
test('canonical storage unavailability fails closed', async () => {
  database.isAvailable = () => false; await expect(service.read(user, 'Bearer original')).rejects.toMatchObject({ status: 503 }); expect(state).not.toHaveBeenCalled();
});
