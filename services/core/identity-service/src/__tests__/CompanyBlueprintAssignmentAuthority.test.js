'use strict';

const { randomUUID } = require('node:crypto');
jest.mock('../AuthorizationState', () => ({ AuthorizationState: jest.fn() }));
jest.mock('../CompanyOwner', () => ({ companyOwner: jest.fn() }));
const { AuthorizationState } = require('../AuthorizationState');
const { companyOwner } = require('../CompanyOwner');
const { CompanyBlueprintAssignmentAuthority } = require('../CompanyBlueprintAssignmentAuthority');
const { COMPANY_BLUEPRINT_ASSIGNMENT_PERMISSIONS, validSource } = require('../../../../../packages/company-blueprint-assignment-contract');
const actorUserId = randomUUID(); const targetId = randomUUID();
const context = { userId: actorUserId, revision: '1', linkRevision: '1', rolesRevision: 'a'.repeat(64) };
const tenant = { id: randomUUID(), version: '1', generation: '1' };
let user; let state; let readState; let query; let revalidate; let database; let authority;
beforeEach(() => {
  jest.clearAllMocks(); const now = Math.floor(Date.now() / 1000);
  user = { iss: 'https://blueprint-assignments.test', sub: 'actual-roleless-owner', actor_type: 'user', token_use: 'access', jti: randomUUID(), exp: now + 600,
    auth_time: now, amr: ['pwd', 'otp'], identity_authorization: context,
    mfa_authorization: { schemaVersion: 1, userId: actorUserId, revision: '1', authTime: now, methods: ['pwd', 'otp'] }, roles: ['admin'], permissions: ['company.apps.assign'] };
  state = { active: true, context, tenant, roles: [], authentication: { required: false, maxAgeSeconds: 86400 } };
  readState = jest.fn(async () => state); AuthorizationState.mockImplementation(() => ({ state: readState }));
  companyOwner.mockResolvedValue({ tenant_id: tenant.id });
  query = jest.fn(async sql => ({ rows: sql.includes('AS tenant_id') ? [{ tenant_id: tenant.id }] : sql.includes('FROM users WHERE')
    ? [{ id: targetId, authorization_revision: '9007199254740993', eligibility_revision: '9223372036854775807', enabled: true }] : [] }));
  database = { isAvailable: () => true, transaction: jest.fn(async operation => operation({ query })) };
  revalidate = jest.fn(async () => tenant); authority = new CompanyBlueprintAssignmentAuthority(database, { issuer: user.iss, revalidate });
});
afterEach(() => jest.useRealTimers());

test('actual roleless ownership produces only the exact twelve-field assignment source in a read-only transaction', async () => {
  const source = await authority.read(user, 'Bearer original');
  expect(Object.keys(source)).toEqual(['schemaVersion', 'companyBlueprintAssignmentsProtocol', 'issuer', 'subject', 'tokenId', 'expiresAt', 'context', 'tenant', 'actorUserId', 'permissions', 'validUntil', 'target']);
  expect(source).toEqual({ schemaVersion: 1, companyBlueprintAssignmentsProtocol: 1, issuer: user.iss, subject: user.sub, tokenId: user.jti, expiresAt: user.exp,
    context, tenant, actorUserId, permissions: ['company.blueprints.assignments.read', 'company.blueprints.assign'], validUntil: user.auth_time + 300, target: null });
  expect(source.permissions).toEqual(COMPANY_BLUEPRINT_ASSIGNMENT_PERMISSIONS); expect(source.permissions).not.toBe(COMPANY_BLUEPRINT_ASSIGNMENT_PERMISSIONS);
  expect(validSource(source, user)).toBe(true); expect(query).not.toHaveBeenCalled();
  expect(database.transaction).toHaveBeenCalledWith(expect.any(Function), { readOnly: true }); expect(companyOwner).toHaveBeenCalledWith({ query }, user);
  expect(revalidate.mock.calls).toEqual([['Bearer original', user], ['Bearer original', user]]);
});
test('only canonical home administration bypasses ownership, without granting or requiring app duties', async () => {
  state.roles = ['admin']; companyOwner.mockResolvedValue(null); user.roles = []; user.permissions = []; user.tenant = { id: randomUUID() };
  const source = await authority.read(user, 'Bearer original', { userId: targetId });
  expect(source.tenant).toEqual(tenant); expect(source.permissions).toEqual(COMPANY_BLUEPRINT_ASSIGNMENT_PERMISSIONS); expect(companyOwner).not.toHaveBeenCalled();
  expect(validSource(source, user, targetId)).toBe(true);
});
test.each([true, false])('positive and disabled own targets expose only their five canonical eligibility fields: %s', async enabled => {
  query.mockResolvedValueOnce({ rows: [{ tenant_id: tenant.id }] }).mockResolvedValueOnce({ rows: [{ id: targetId, authorization_revision: '9007199254740993', eligibility_revision: '9223372036854775807', enabled, email: 'never project', display_name: 'never project' }] });
  const source = await authority.read(user, 'Bearer original', { userId: targetId });
  expect(source.target).toEqual({ id: targetId, revision: '9007199254740993', eligibilityRevision: '9223372036854775807', enabled, deleted: false });
  expect(validSource(source, user, targetId)).toBe(true); expect(query).toHaveBeenCalledTimes(2);
});
test('deleted own targets retain their immutable negative generation without recreating a profile', async () => {
  query.mockResolvedValueOnce({ rows: [{ tenant_id: tenant.id }] }).mockResolvedValueOnce({ rows: [] }).mockResolvedValueOnce({ rows: [{ revision: '9223372036854775807' }] });
  const source = await authority.read(user, 'Bearer original', { userId: targetId });
  expect(source.target).toEqual({ id: targetId, revision: null, eligibilityRevision: '9223372036854775807', enabled: false, deleted: true });
  expect(validSource(source, user, targetId)).toBe(true); expect(query).toHaveBeenCalledTimes(3);
});
test.each([null, randomUUID()])('foreign or missing ownership %s is rejected before reading target account or tombstone', async home => {
  query.mockResolvedValueOnce({ rows: [{ tenant_id: home }] }); await expect(authority.read(user, 'Bearer original', { userId: targetId })).rejects.toMatchObject({ status: 404 }); expect(query).toHaveBeenCalledTimes(1);
});
test('a retained own resource owner with no account or deletion evidence is not invented', async () => {
  query.mockResolvedValueOnce({ rows: [{ tenant_id: tenant.id }] }).mockResolvedValue({ rows: [] });
  await expect(authority.read(user, 'Bearer original', { userId: targetId })).rejects.toMatchObject({ status: 404 });
});
test.each([{}, [], { userId: targetId, tenantId: tenant.id }, { userId: 'alias' }, { userId: 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA' }])('a targeted source requires exactly one canonical UUID selector: %j', async body => {
  await expect(authority.read(user, 'Bearer original', body)).rejects.toMatchObject({ status: 400 }); expect(revalidate).not.toHaveBeenCalled();
});
test.each([null, 'policy-administrator', 'license-administrator'])('claimed token administration and unrelated canonical roles cannot substitute ownership: %s', async role => {
  state.roles = role ? [role] : []; companyOwner.mockResolvedValue(null);
  await expect(authority.read(user, 'Bearer original')).rejects.toMatchObject({ status: 403 }); expect(query).not.toHaveBeenCalled();
});
test('an owner record from another tenant is not current home authority', async () => {
  companyOwner.mockResolvedValue({ tenant_id: randomUUID() }); await expect(authority.read(user, 'Bearer original')).rejects.toMatchObject({ status: 403 });
});
test.each([{ actor_type: 'application' }, { actor_type: 'workload' }, { token_use: 'refresh' }, { iss: 'https://foreign.test' }, { identity_authorization: null }, { jti: '' }, { exp: '9999999999' }])('noncanonical original human claims cannot enter verification: %j', async patch => {
  await expect(authority.read({ ...user, ...patch }, 'Bearer original')).rejects.toMatchObject({ status: 403 }); expect(revalidate).not.toHaveBeenCalled();
});
test.each([undefined, '', 'Basic original', 'Bearer original token', 'bearer original', 'Bearer ' + 'a'.repeat(16384)])('the original bearer is mandatory: %s', async authorization => {
  await expect(authority.read(user, authorization)).rejects.toMatchObject({ status: 401 }); expect(revalidate).not.toHaveBeenCalled();
});
test.each(['missing', 'password-only', 'unbound', 'stale', 'future'])('independently bound fresh MFA is mandatory even for a read-only source: %s', async mode => {
  if (mode === 'missing') delete user.mfa_authorization;
  if (mode === 'password-only') { user.amr = ['pwd']; user.mfa_authorization.methods = ['pwd']; }
  if (mode === 'unbound') user.mfa_authorization.userId = randomUUID();
  if (mode === 'stale') { user.auth_time -= 301; user.mfa_authorization.authTime -= 301; }
  if (mode === 'future') { user.auth_time += 6; user.mfa_authorization.authTime += 6; }
  await expect(authority.read(user, 'Bearer original')).rejects.toMatchObject({ status: 428 }); expect(revalidate).not.toHaveBeenCalled();
});
test.each(['inactive', 'userId', 'revision', 'linkRevision', 'rolesRevision', 'tenant', 'version', 'generation', 'authentication'])('changed canonical %s discards the original request', async change => {
  if (change === 'inactive') state.active = false;
  if (['userId', 'revision', 'linkRevision', 'rolesRevision'].includes(change)) state.context = { ...context, [change]: change === 'userId' ? randomUUID() : change === 'rolesRevision' ? 'b'.repeat(64) : '2' };
  if (change === 'tenant') state.tenant = { ...tenant, id: randomUUID() };
  if (['version', 'generation'].includes(change)) state.tenant = { ...tenant, [change]: '2' };
  if (change === 'authentication') state.authentication = { required: true, maxAgeSeconds: 0 };
  await expect(authority.read(user, 'Bearer original')).rejects.toMatchObject({ status: 401 }); expect(companyOwner).not.toHaveBeenCalled();
});
test.each(['id', 'version', 'generation'])('a changed final tenant %s discards the read-only source', async field => {
  revalidate.mockResolvedValueOnce(tenant).mockResolvedValueOnce({ ...tenant, [field]: field === 'id' ? randomUUID() : '2' });
  await expect(authority.read(user, 'Bearer original')).rejects.toMatchObject({ status: 401 });
});
test.each([401, 503])('final original bearer denial %i is preserved', async status => {
  revalidate.mockResolvedValueOnce(tenant).mockRejectedValueOnce(Object.assign(new Error('Original bearer withdrawn'), { status }));
  await expect(authority.read(user, 'Bearer original')).rejects.toMatchObject({ status });
});
test.each(['token', 'mfa'])('the original %s deadline cannot expire during the final source check', async mode => {
  jest.useFakeTimers().setSystemTime(user.auth_time * 1000); if (mode === 'token') user.exp = user.auth_time + 10;
  revalidate.mockResolvedValueOnce(tenant).mockImplementationOnce(async () => { jest.setSystemTime((user.auth_time + (mode === 'token' ? 10 : 301)) * 1000); return tenant; });
  await expect(authority.read(user, 'Bearer original')).rejects.toMatchObject({ status: 401 });
});
test('the validity ceiling is the original token even with a longer canonical role policy', async () => {
  user.exp = user.auth_time + 45; state.authentication = { required: true, maxAgeSeconds: 86400 };
  expect((await authority.read(user, 'Bearer original')).validUntil).toBe(user.exp);
});
test('accepted five-second MFA clock tolerance never extends the source beyond observed now plus 300 seconds', async () => {
  jest.useFakeTimers().setSystemTime(user.auth_time * 1000); const now = user.auth_time; user.auth_time += 5; user.mfa_authorization.authTime += 5;
  expect((await authority.read(user, 'Bearer original')).validUntil).toBe(now + 300);
});
test('unavailable storage cannot fall back to roles or app rights', async () => {
  database.isAvailable = () => false; await expect(authority.read(user, 'Bearer original')).rejects.toMatchObject({ status: 503 }); expect(revalidate).not.toHaveBeenCalled();
});
test('SQL receiving failures stay unavailable instead of becoming a home-admin grant', async () => {
  companyOwner.mockRejectedValue(Object.assign(new Error('Missing receiving evidence'), { code: '42501' }));
  await expect(authority.read(user, 'Bearer original')).rejects.toMatchObject({ status: 503, cause: { code: '42501' } });
});
test('malformed canonical target records cannot mint a successful source', async () => {
  query.mockResolvedValueOnce({ rows: [{ tenant_id: tenant.id }] }).mockResolvedValueOnce({ rows: [{ id: targetId, authorization_revision: '1', eligibility_revision: '0', enabled: true }] });
  await expect(authority.read(user, 'Bearer original', { userId: targetId })).rejects.toMatchObject({ status: 401 });
});
