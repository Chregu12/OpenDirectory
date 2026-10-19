'use strict';

const { randomUUID } = require('node:crypto');
jest.mock('../AuthorizationState', () => ({ AuthorizationState: jest.fn() }));
jest.mock('../CompanyOwner', () => ({ companyOwner: jest.fn() }));
const { AuthorizationState } = require('../AuthorizationState');
const { companyOwner } = require('../CompanyOwner');
const { CompanyLicenseAuthority } = require('../CompanyLicenseAuthority');
const { COMPANY_LICENSE_PERMISSIONS, poolValues, expectedVersion, pagination, assignmentValues } = require('../../../../../packages/company-license-contract');
const userId = randomUUID(); const tenant = { id: randomUUID(), version: '1', generation: '1' }; const context = { userId, revision: '1', linkRevision: '1', rolesRevision: 'a'.repeat(64) };
let user; let state; let query; let revalidate; let database; let authority;
beforeEach(() => {
  jest.clearAllMocks(); const now = Math.floor(Date.now() / 1000);
  user = { iss: 'https://company-license.test', sub: 'actual-roleless-owner', jti: randomUUID(), actor_type: 'user', exp: now + 600, auth_time: now, amr: ['pwd', 'otp'], identity_authorization: context, mfa_authorization: { schemaVersion: 1, userId, revision: '1', authTime: now, methods: ['pwd', 'otp'] }, roles: ['admin'], permissions: ['licenses.assignments.manage'] };
  state = { active: true, context, tenant, roles: [], authentication: { required: true, maxAgeSeconds: 300 } };
  AuthorizationState.mockImplementation(() => ({ state: jest.fn(async () => state) })); companyOwner.mockResolvedValue({ tenant_id: tenant.id });
  query = jest.fn(async () => ({ rows: [] })); database = { isAvailable: () => true, transaction: async operation => operation({ query }) };
  revalidate = jest.fn(async () => tenant); authority = new CompanyLicenseAuthority(database, { issuer: user.iss, revalidate });
});
test('actual roleless ownership gives only three own-company app duties and an original bounded MFA deadline', async () => {
  const source = await authority.read(user, 'Bearer original'); expect(source.permissions).toEqual(COMPANY_LICENSE_PERMISSIONS); expect(source.actorUserId).toBe(userId); expect(source.validUntil).toBe(user.auth_time + 300); expect(source.target).toBeNull(); expect(revalidate).toHaveBeenCalledTimes(2);
});
test('claimed global administration cannot replace actual current ownership or canonical home administration', async () => {
  companyOwner.mockResolvedValue(null); await expect(authority.read(user, 'Bearer original')).rejects.toMatchObject({ status: 403 }); expect(query).not.toHaveBeenCalled();
});
test('actual canonical administration still receives only its home tenant and no global licensing role', async () => {
  state.roles = ['admin']; const source = await authority.read(user, 'Bearer original'); expect(source.tenant).toEqual(tenant); expect(source.permissions).not.toContain('licenses.assignments.manage'); expect(companyOwner).not.toHaveBeenCalled();
});
test.each([true, false])('a current own employee exposes exact eligibility, not a profile or caller role: %s', async enabled => {
  const target = randomUUID(); query.mockResolvedValueOnce({ rows: [{ tenant_id: tenant.id }] }).mockResolvedValueOnce({ rows: [{ id: target, authorization_revision: '9007199254740993', eligibility_revision: '9223372036854775807', enabled }] });
  expect((await authority.read(user, 'Bearer original', { userId: target })).target).toEqual({ id: target, revision: '9007199254740993', eligibilityRevision: '9223372036854775807', enabled, deleted: false });
});
test('retained own deletion remains explicitly negative for controlled license release', async () => {
  const target = randomUUID(); query.mockResolvedValueOnce({ rows: [{ tenant_id: tenant.id }] }).mockResolvedValueOnce({ rows: [] }).mockResolvedValueOnce({ rows: [{ revision: '9' }] });
  expect((await authority.read(user, 'Bearer original', { userId: target })).target).toEqual({ id: target, revision: null, eligibilityRevision: '9', enabled: false, deleted: true });
});
test.each([null, 'foreign'])('foreign or unowned recipients fail before eligibility or deletion lookup: %s', async tenantId => {
  query.mockResolvedValue({ rows: [{ tenant_id: tenantId }] }); await expect(authority.read(user, 'Bearer original', { userId: randomUUID() })).rejects.toMatchObject({ status: 404 }); expect(query).toHaveBeenCalledTimes(1);
});
test.each([{}, [], { userId: 'alias' }, { userId: 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA' }, { userId, tenantId: tenant.id }])('unsupported selector cannot enter authority storage: %j', async body => {
  await expect(authority.read(user, 'Bearer original', body)).rejects.toMatchObject({ status: 400 }); expect(revalidate).not.toHaveBeenCalled();
});
test('fresh bound MFA is required even for catalog reads', async () => { user.auth_time -= 301; await expect(authority.read(user, 'Bearer original')).rejects.toMatchObject({ status: 428 }); expect(query).not.toHaveBeenCalled(); });
test('a current actor or final tenant-generation change discards the source', async () => {
  state.context = { ...context, revision: '2' }; await expect(authority.read(user, 'Bearer original')).rejects.toMatchObject({ status: 401 }); state.context = context;
  revalidate.mockResolvedValueOnce(tenant).mockResolvedValueOnce({ ...tenant, generation: '2' }); await expect(authority.read(user, 'Bearer original')).rejects.toMatchObject({ status: 401 });
});
test('workloads and unavailable canonical storage cannot become company administrators', async () => {
  await expect(authority.read({ ...user, actor_type: 'application' }, 'Bearer original')).rejects.toMatchObject({ status: 403 }); database.isAvailable = () => false; await expect(authority.read(user, 'Bearer original')).rejects.toMatchObject({ status: 503 });
});
const values = { name: 'Actual company application', vendor: 'Vendor', description: '', totalSeats: 1, reason: 'Explicit reviewed local license inventory' };
test('finite new pools normalize explicit local values without prices or unlimited licensing', () => { expect(poolValues({ ...values, name: '  Actual company application  ' })).toEqual(values); expect(pagination({ page: '2', limit: '25', search: '%' }, true)).toEqual({ page: 2, limit: 25, search: '%' }); });
test.each([{ ...values, totalSeats: 0 }, { ...values, totalSeats: 10001 }, { ...values, totalSeats: 1.5 }, { ...values, vendor: '' }, { ...values, name: 'bad\nname' }, { ...values, reason: 'short' }, { ...values, tenantId: tenant.id }])('pool request rejects unsupported or unbounded input: %j', input => { expect(() => poolValues(input)).toThrow(); });
test('original exact pool versions and explicit target confirmations cannot be replaced by wildcards or tenant selectors', () => {
  const id = randomUUID(); expect(expectedVersion(id, `"company-pool-${id}-9223372036854775807"`)).toBe('9223372036854775807'); expect(() => expectedVersion(id, undefined)).toThrow(); expect(() => expectedVersion(id, '*')).toThrow(); expect(() => expectedVersion(id, `"company-pool-${id}-9223372036854775808"`)).toThrow();
  expect(assignmentValues({ userId, confirm: true, reason: values.reason })).toEqual({ userId, confirm: true, reason: values.reason }); expect(() => assignmentValues({ userId, confirm: false, reason: values.reason })).toThrow(); expect(() => pagination({ tenantId: tenant.id })).toThrow();
});
