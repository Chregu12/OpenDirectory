'use strict';

const { randomUUID } = require('node:crypto');
jest.mock('../AuthorizationState', () => ({ AuthorizationState: jest.fn() }));
jest.mock('../CompanyOwner', () => ({ companyOwner: jest.fn() }));
const { AuthorizationState } = require('../AuthorizationState');
const { companyOwner } = require('../CompanyOwner');
const { CompanyBlueprintAuthority } = require('../CompanyBlueprintAuthority');
const { COMPANY_BLUEPRINT_PERMISSIONS, validSource } = require('../../../../../packages/company-blueprint-contract');
const userId = randomUUID(); const tenant = { id: randomUUID(), version: '1', generation: '1' };
const context = { userId, revision: '1', linkRevision: '1', rolesRevision: 'a'.repeat(64) };
let user; let state; let readState; let query; let revalidate; let database; let authority;
beforeEach(() => {
  jest.clearAllMocks(); const now = Math.floor(Date.now() / 1000);
  user = { iss: 'https://company-blueprint.test', sub: 'actual-roleless-owner', jti: randomUUID(), actor_type: 'user', token_use: 'access', exp: now + 600,
    auth_time: now, amr: ['pwd', 'otp'], identity_authorization: context,
    mfa_authorization: { schemaVersion: 1, userId, revision: '1', authTime: now, methods: ['pwd', 'otp'] },
    roles: ['admin'], permissions: ['policies.publish', 'company.apps.assign'] };
  state = { active: true, context, tenant, roles: [], authentication: { required: false, maxAgeSeconds: 86400 } };
  readState = jest.fn(async () => state); AuthorizationState.mockImplementation(() => ({ state: readState }));
  companyOwner.mockResolvedValue({ tenant_id: tenant.id }); query = jest.fn(async () => ({ rows: [] }));
  database = { isAvailable: () => true, transaction: jest.fn(async operation => operation({ query })) };
  revalidate = jest.fn(async () => tenant); authority = new CompanyBlueprintAuthority(database, { issuer: user.iss, revalidate });
});
afterEach(() => jest.useRealTimers());
test('actual roleless ownership returns exactly the separate eleven-field contract and only its three product duties', async () => {
  const result = await authority.read(user, 'Bearer original');
  expect(Object.keys(result)).toEqual(['schemaVersion', 'companyBlueprintProtocol', 'issuer', 'subject', 'tokenId', 'expiresAt', 'context', 'tenant', 'actorUserId', 'permissions', 'validUntil']);
  expect(result).toEqual({ schemaVersion: 1, companyBlueprintProtocol: 1, issuer: user.iss, subject: user.sub, tokenId: user.jti, expiresAt: user.exp,
    context, tenant, actorUserId: userId, permissions: ['company.blueprints.read', 'company.blueprints.manage', 'company.blueprints.publish'], validUntil: user.auth_time + 300 });
  expect(result.permissions).toEqual(COMPANY_BLUEPRINT_PERMISSIONS); expect(result.permissions).not.toBe(COMPANY_BLUEPRINT_PERMISSIONS);
  expect(validSource(result, user)).toBe(true);
  expect(readState).toHaveBeenCalledWith(user.iss, user.sub); expect(companyOwner).toHaveBeenCalledWith({ query }, user);
  expect(database.transaction).toHaveBeenCalledWith(expect.any(Function), { readOnly: true }); expect(query).not.toHaveBeenCalled();
  expect(revalidate.mock.calls).toEqual([['Bearer original', user], ['Bearer original', user]]);
});
test('actual canonical home administration receives the actual home tenant, never token-selected roles or tenants', async () => {
  state.roles = ['admin']; companyOwner.mockResolvedValue(null); user.roles = []; user.permissions = []; user.tenant = { id: randomUUID() };
  const source = await authority.read(user, 'Bearer original'); expect(source.tenant).toEqual(tenant); expect(source.permissions).toEqual(COMPANY_BLUEPRINT_PERMISSIONS); expect(companyOwner).not.toHaveBeenCalled();
});
test.each([null, 'policy-administrator', 'license-administrator', 'directory-reader'])('claimed token administration cannot replace current own-company authority: %s', async role => {
  state.roles = role ? [role] : []; companyOwner.mockResolvedValue(null);
  await expect(authority.read(user, 'Bearer original')).rejects.toMatchObject({ status: 403 }); expect(revalidate).toHaveBeenCalledTimes(1);
});
test('ownership evidence for a different home cannot authorize the current company source', async () => {
  companyOwner.mockResolvedValue({ tenant_id: randomUUID() }); await expect(authority.read(user, 'Bearer original')).rejects.toMatchObject({ status: 403 });
});
test.each(['application', 'workload', undefined])('non-human %s actors cannot enter source verification', async actorType => {
  user.actor_type = actorType; await expect(authority.read(user, 'Bearer original')).rejects.toMatchObject({ status: 403 }); expect(revalidate).not.toHaveBeenCalled();
});
test.each([null, {}, { userId }])('missing or malformed original identity contexts fail closed: %j', async identity => {
  user.identity_authorization = identity; await expect(authority.read(user, 'Bearer original')).rejects.toMatchObject({ status: 403 }); expect(revalidate).not.toHaveBeenCalled();
});
test('a foreign issuer cannot reuse actual ownership', async () => {
  user.iss = 'https://foreign.test'; await expect(authority.read(user, 'Bearer original')).rejects.toMatchObject({ status: 403 }); expect(revalidate).not.toHaveBeenCalled();
});
test.each([undefined, '', 'Basic original', 'Bearer original token', 'bearer original', 'Bearer ' + 'a'.repeat(16384)])('the actual original bearer is mandatory: %s', async authorization => {
  await expect(authority.read(user, authorization)).rejects.toMatchObject({ status: 401 }); expect(revalidate).not.toHaveBeenCalled(); expect(readState).not.toHaveBeenCalled();
});
test.each(['missing', 'password-only', 'unbound', 'stale', 'future'])('independently bound fresh MFA is mandatory even for reads and a non-MFA role policy: %s', async mode => {
  if (mode === 'missing') delete user.mfa_authorization;
  if (mode === 'password-only') { user.amr = ['pwd']; user.mfa_authorization.methods = ['pwd']; }
  if (mode === 'unbound') user.mfa_authorization.userId = randomUUID();
  if (mode === 'stale') { user.auth_time -= 301; user.mfa_authorization.authTime -= 301; }
  if (mode === 'future') { user.auth_time += 6; user.mfa_authorization.authTime += 6; }
  await expect(authority.read(user, 'Bearer original')).rejects.toMatchObject({ status: 428 }); expect(revalidate).not.toHaveBeenCalled();
});
test.each(['inactive', 'user', 'revision', 'linkRevision', 'rolesRevision', 'tenant', 'version', 'generation', 'authentication'])('canonical source changes discard the original authority: %s', async change => {
  if (change === 'inactive') state.active = false;
  if (change === 'user') state.context = { ...context, userId: randomUUID() };
  if (['revision', 'linkRevision'].includes(change)) state.context = { ...context, [change]: '2' };
  if (change === 'rolesRevision') state.context = { ...context, rolesRevision: 'b'.repeat(64) };
  if (change === 'tenant') state.tenant = { ...tenant, id: randomUUID() };
  if (['version', 'generation'].includes(change)) state.tenant = { ...tenant, [change]: '2' };
  if (change === 'authentication') state.authentication = { required: true, maxAgeSeconds: 0 };
  await expect(authority.read(user, 'Bearer original')).rejects.toMatchObject({ status: 401 }); expect(companyOwner).not.toHaveBeenCalled();
});
test.each([401, 503])('failure of the original tenant authority cannot mint a source: %i', async status => {
  revalidate.mockRejectedValue(Object.assign(new Error('Actual original authority unavailable'), { status }));
  await expect(authority.read(user, 'Bearer original')).rejects.toMatchObject({ status }); expect(readState).not.toHaveBeenCalled();
});
test.each(['id', 'version', 'generation'])('final original tenant %s changes discard the read-only result', async field => {
  revalidate.mockResolvedValueOnce(tenant).mockResolvedValueOnce({ ...tenant, [field]: field === 'id' ? randomUUID() : '2' });
  await expect(authority.read(user, 'Bearer original')).rejects.toMatchObject({ status: 401 });
});
test.each([401, 503])('a final revoked or unavailable original bearer discards the result: %i', async status => {
  revalidate.mockResolvedValueOnce(tenant).mockRejectedValueOnce(Object.assign(new Error('Original source withdrawn'), { status }));
  await expect(authority.read(user, 'Bearer original')).rejects.toMatchObject({ status });
});
test('canonical expiry, not a refreshed role policy, bounds source validity', async () => {
  user.exp = user.auth_time + 45; state.authentication = { required: true, maxAgeSeconds: 86400 };
  expect((await authority.read(user, 'Bearer original')).validUntil).toBe(user.exp);
});
test.each([1, 5])('accepted future MFA clock tolerance of %i seconds never makes the source live beyond now plus 300 seconds', async offset => {
  jest.useFakeTimers().setSystemTime(user.auth_time * 1000); const now = user.auth_time;
  user.auth_time += offset; user.mfa_authorization.authTime += offset;
  const source = await authority.read(user, 'Bearer original'); expect(source.validUntil).toBe(now + 300); expect(validSource(source, user)).toBe(true);
});
test.each(['mfa', 'token'])('time passing during the final authority call cannot extend the captured %s deadline', async mode => {
  jest.useFakeTimers().setSystemTime(user.auth_time * 1000);
  if (mode === 'token') user.exp = user.auth_time + 10;
  revalidate.mockImplementationOnce(async () => tenant).mockImplementationOnce(async () => {
    jest.setSystemTime((user.auth_time + (mode === 'mfa' ? 301 : 10)) * 1000); return tenant;
  });
  await expect(authority.read(user, 'Bearer original')).rejects.toMatchObject({ status: 401 });
});
test('unavailable canonical storage prevents all source and owner checks', async () => {
  database.isAvailable = () => false; await expect(authority.read(user, 'Bearer original')).rejects.toMatchObject({ status: 503 });
  expect(revalidate).not.toHaveBeenCalled(); expect(database.transaction).not.toHaveBeenCalled();
});
test('missing current company-owner receiving evidence remains unavailable, not a fallback grant', async () => {
  companyOwner.mockRejectedValue(Object.assign(new Error('company_owner_evidence_unavailable'), { status: 503 }));
  await expect(authority.read(user, 'Bearer original')).rejects.toMatchObject({ status: 503 });
});
test('canonical SQL or receiving failures remain unavailable rather than an administrative fallback', async () => {
  companyOwner.mockRejectedValue(Object.assign(new Error('Company activation receiving unavailable'), { code: '42501' }));
  await expect(authority.read(user, 'Bearer original')).rejects.toMatchObject({ status: 503, cause: { code: '42501' } });
});
