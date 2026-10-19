'use strict';

const { randomUUID } = require('node:crypto');
const { mayUseDirectory, requireDirectoryPermissions } = require('../DirectoryAuthority');
const { companyDirectoryPermissions, COMPANY_DIRECTORY_PERMISSIONS } = require('../CompanyOwner');
const { getIdentityPermissions } = require('../middleware/identityAccess');
const userId = randomUUID(); const tenantId = randomUUID(); const authTime = Math.floor(Date.now() / 1000);
const user = { iss: 'https://owner.test', sub: 'original-owner', actor_type: 'user', roles: [], auth_time: authTime, amr: ['pwd', 'otp'],
  identity_authorization: { userId, revision: '1', linkRevision: '1', rolesRevision: 'a'.repeat(64) },
  mfa_authorization: { schemaVersion: 1, userId, revision: '1', authTime, methods: ['pwd', 'otp'] } };
let client; let owner;
beforeEach(() => {
  owner = { id: randomUUID(), issuer: user.iss, subject: user.sub, tenant_id: tenantId, active: true, valid: true };
  client = { query: jest.fn(async sql => {
    if (sql.startsWith('SELECT identity_authority_actor_home')) return { rows: [{ tenant_id: tenantId }] };
    if (sql.startsWith('SELECT owner.*')) return { rows: owner ? [owner] : [] };
    if (sql === 'SELECT identity_company_activation_receiving()') return { rows: [] };
    if (sql === 'SELECT identity_directory_ou_receiving()') return { rows: [] };
    throw new Error('Unexpected authority query');
  }) };
});
test('the actual active original company owner receives only the bounded own-directory permissions, not a global role', async () => {
  expect(getIdentityPermissions(user)).toEqual([]); expect(mayUseDirectory(user, ['users.create'])).toBe(true);
  expect(await companyDirectoryPermissions(client, user)).toEqual(COMPANY_DIRECTORY_PERMISSIONS);
  await expect(requireDirectoryPermissions(client, user, ['users.create', 'groups.members.manage'])).resolves.toBeUndefined();
  expect(client.query).toHaveBeenCalledWith('SELECT identity_company_activation_receiving()');
});
test.each(['users.delete', 'users.sessions.invalidate', 'identities.roles.manage', 'licenses.sources.manage'])('company ownership cannot acquire unrelated duty %s', async permission => {
  expect(mayUseDirectory(user, [permission])).toBe(false); await expect(requireDirectoryPermissions(client, user, [permission])).rejects.toMatchObject({ status: 403 }); expect(client.query).not.toHaveBeenCalled();
});
test.each(['ous.update', 'ous.delete'])('actual company ownership grants %s only through the current canonical OU receiver', async permission => {
  await expect(requireDirectoryPermissions(client, user, [permission])).resolves.toBeUndefined(); expect(client.query).toHaveBeenCalledWith('SELECT identity_directory_ou_receiving()');
  const original = client.query.getMockImplementation(); client.query.mockImplementation(sql => sql === 'SELECT identity_directory_ou_receiving()' ? Promise.reject(new Error('Receiver missing')) : original(sql));
  await expect(requireDirectoryPermissions(client, user, [permission])).rejects.toMatchObject({ status: 503 });
});
test('invented owner claims and company permission arrays do not replace an actual owner source', async () => {
  owner = null; const forged = { ...user, companyOwner: true, company_permissions: COMPANY_DIRECTORY_PERMISSIONS };
  expect(await companyDirectoryPermissions(client, forged)).toEqual([]); await expect(requireDirectoryPermissions(client, forged, ['users.create'])).rejects.toMatchObject({ status: 403 });
});
test.each([{ active: false }, { subject: 'foreign-subject' }, { issuer: 'https://foreign.test' }, { tenant_id: randomUUID() }])('an inactive, foreign or rehomed source is not company-directory authority: %j', async change => {
  owner = { ...owner, ...change }; expect(await companyDirectoryPermissions(client, user)).toEqual([]);
});
test('old or missing independently bound MFA cannot activate the owner path', async () => {
  for (const changed of [{ ...user, amr: ['pwd'] }, { ...user, auth_time: authTime - 301, mfa_authorization: { ...user.mfa_authorization, authTime: authTime - 301 } }]) {
    expect(mayUseDirectory(changed, ['users.create'])).toBe(false); expect(await companyDirectoryPermissions(client, changed)).toEqual([]);
  }
  expect(client.query).not.toHaveBeenCalled();
});
test('corrupt retained owner evidence fails closed rather than falling back to a caller claim', async () => {
  owner.valid = false; await expect(requireDirectoryPermissions(client, user, ['users.read'])).rejects.toMatchObject({ status: 503 });
});
test('existing explicit directory duties preserve their normal authorization path without reading company sources', async () => {
  await expect(requireDirectoryPermissions(client, { ...user, roles: ['user-administrator'] }, ['users.update'])).resolves.toBeUndefined(); expect(client.query).not.toHaveBeenCalled();
});
test('the generated directory API preserves conditional writes including canonical OU mutations', () => {
  const document = require('../../scripts/organization-openapi').organizationOpenApi();
  expect(document.paths['/api/users'].post.requestBody.content['application/json'].schema).toMatchObject({ additionalProperties: false, required: ['username', 'email'] });
  expect(document.paths['/api/users'].post.requestBody.content['application/json'].schema.properties.enabled).toBeUndefined();
  expect(document.paths['/api/groups/{id}/members'].post.parameters).toContainEqual(expect.objectContaining({ name: 'If-Match', required: true }));
  expect(document.paths['/api/ous/{id}'].put.parameters).toContainEqual(expect.objectContaining({ name: 'If-Match', required: true }));
  expect(document.paths['/api/ous/{id}'].delete.parameters).toContainEqual(expect.objectContaining({ name: 'If-Match', required: true }));
  expect(document.components.schemas.DirectoryOu.required).toContain('memberCount');
  expect(document.paths['/api/ous/{id}/members'].post.parameters).toContainEqual(expect.objectContaining({ name: 'If-Match', required: true }));
  expect(document.paths['/api/ous/{id}/members'].post.requestBody.content['application/json'].schema).toMatchObject({ additionalProperties: false, required: ['userId'], properties: { userId: { format: 'uuid' } } });
  expect(document.paths['/api/ous/{id}/members/{membershipId}'].delete.responses[200]).toBeDefined();
  expect(document.paths['/api/ous/{id}/members/{membershipId}'].delete.responses[204]).toBeUndefined();
  expect(document.paths['/api/ous/{id}/members'].get.parameters.filter(parameter => parameter.in === 'query').map(parameter => parameter.name)).toEqual(['page', 'limit']);
  const operations = Object.values(document.paths).flatMap(path => Object.values(path).map(operation => operation.operationId)); expect(new Set(operations).size).toBe(operations.length);
});
