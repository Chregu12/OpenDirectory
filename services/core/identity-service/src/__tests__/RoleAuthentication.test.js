'use strict';
jest.mock('../AuthorityCheckpoint', () => ({ ...jest.requireActual('../AuthorityCheckpoint'), beginAuthorityCheckpoint: jest.fn(async () => async () => {}) }));

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { RoleAuthentication, policyEtag } = require('../RoleAuthentication');
const { getIdentityPermissions } = require('../middleware/identityAccess');
const { readRoleState } = require('../AuthorizationState');
const { acceptsRoleAuthentication } = require('../../../../../packages/role-authentication-contract');
const { PROTECTED } = require('../../../../../packages/directory-role-contract');
const userId = crypto.randomUUID();
const actor = { iss: 'https://issuer.test', sub: 'security-operator', actor_type: 'user', roles: ['authentication-policy-administrator'],
  identity_authorization: { userId, revision: '1', linkRevision: '1', rolesRevision: 'a'.repeat(64) },
  auth_time: Math.floor(Date.now() / 1000), amr: ['pwd','otp'],
  mfa_authorization: { schemaVersion: 1, userId, revision: '1', authTime: Math.floor(Date.now() / 1000), methods: ['pwd','otp'] } };
const input = { required: true, maxAgeSeconds: 300, reason: 'Reviewed least privilege policy' };
let row; let database; let store;
test.each(['identity-service','oauth-provider'])('the %s image includes the shared live role-assurance contract', service => {
  const dockerfile = fs.readFileSync(path.join(__dirname,'../../..',service,'Dockerfile'),'utf8');
  expect(dockerfile).toContain('COPY packages/role-authentication-contract.js /packages/role-authentication-contract.js');
});
beforeEach(() => {
  const grant = { id: crypto.randomUUID(),role:'authentication-policy-administrator',policy_version:'1',activation_version:'1',activation_required:false,max_duration_seconds:28800 };
  actor.identity_authorization.rolesRevision = crypto.createHash('sha256').update(JSON.stringify([[[grant.id,grant.role,'1','1']],[[grant.role,'1']]])).digest('hex');
  row = { role: 'license-manager', version: '1', mfa_required: false, max_age_seconds: 3600 };
  database = { query: jest.fn(async sql => {
    if (sql.includes('FROM users JOIN')) return { rows: [{ id:userId,enabled:true,revision:'1',link_revision:'1' }] };
    if (sql.includes('FROM identity_role_assignments')) return { rows: [grant] };
    if (sql.includes('role=ANY')) return { rows: [{ role:grant.role,version:'1',mfa_required:true,max_age_seconds:300 }] };
    if (sql.startsWith('SELECT *')) return { rows: [{ ...row }] };
    if (sql.startsWith('UPDATE')) { row = { ...row, version: String(BigInt(row.version) + 1n), mfa_required: input.required, max_age_seconds: input.maxAgeSeconds }; return { rows: [{ ...row }] }; }
    return { rows: [] };
  }), transaction: jest.fn() };
  database.transaction.mockImplementation(operation => operation(database)); store = new RoleAuthentication(database, { revalidate: jest.fn(async () => {}) });
});
test('policy duties are separate, protected and reveal only the named policy', async () => {
  expect(PROTECTED).toContain('authentication-policy-administrator');
  expect(getIdentityPermissions(actor)).toEqual(['authentication.policies.read','authentication.policies.manage']);
  expect(getIdentityPermissions({ roles: ['role-administrator','application-authentication-administrator'] })).not.toContain('authentication.policies.manage');
  const result = await store.get(row.role, { ...actor, roles: ['authentication-policy-reader'] });
  expect(Object.keys(result).sort()).toEqual(['canManage','locked','maxAgeSeconds','protected','required','requiresFreshMfa','role','version']);
  expect(result).toMatchObject({ canManage: false, required: false, role: row.role });
  await expect(store.change(row.role, policyEtag(row.role,'1'), input, { ...actor,roles: ['authentication-policy-reader'] })).rejects.toMatchObject({ status: 403 });
});
test('strict conditional changes capture the verified actor and reviewed reason atomically', async () => {
  const result = await store.change(row.role,policyEtag(row.role,'1'),input,actor);
  expect(result).toMatchObject({ version: '2', required: true, maxAgeSeconds: 300 });
  expect(database.transaction).toHaveBeenCalledWith(expect.any(Function), { actor: JSON.stringify({ issuer: actor.iss, subject: actor.sub,userId }) });
  expect(database.query).toHaveBeenCalledWith(expect.stringContaining('FOR UPDATE'),[row.role]);
  expect(database.query).toHaveBeenCalledWith(expect.stringContaining('set_config'),[input.reason]);
  await expect(store.change(row.role,policyEtag(row.role,'1'),input,actor)).rejects.toMatchObject({ status: 412 });
});
test.each([{ required: 'true' },{ maxAgeSeconds: 299 },{ maxAgeSeconds: 86401 },{ maxAgeSeconds: '300' },{ reason: 'short' },{ reason: 'reason\ncontrol' },{ roles: ['admin'] },{ version: '1' }])('unreviewed or injected fields cannot change a role rule: %j', async patch => {
  await expect(store.change(row.role,policyEtag(row.role,'1'),{ ...input,...patch },actor)).rejects.toMatchObject({ status: 400 });
  expect(database.transaction).not.toHaveBeenCalled();
});
test('global duties are needed for protected and baseline user policies; the policy-management minimum is fixed', async () => {
  for (const role of ['admin','role-administrator','user']) {
    row.role = role;
    await expect(store.change(role,policyEtag(role,'1'),input,actor)).rejects.toMatchObject({ status: 403 });
  }
  row = { role: 'authentication-policy-administrator',version: '1',mfa_required: true,max_age_seconds: 300 };
  expect(await store.get(row.role,actor)).toMatchObject({ locked: true, canManage: false });
  await expect(store.change(row.role,policyEtag(row.role,'1'),input,{ ...actor,roles: ['admin'] })).rejects.toMatchObject({ status: 409 });
});
test.each([{ actor_type: 'application' },{ identity_authorization: undefined },{ amr: ['otp'] },{ mfa_authorization: undefined },{ auth_time: Math.floor(Date.now()/1000)-301 }])('canonical human and fresh real MFA cannot be substituted: %j', async patch => {
  await expect(store.change(row.role,policyEtag(row.role,'1'),input,{ ...actor,...patch })).rejects.toMatchObject({ status: patch.actor_type || Object.hasOwn(patch,'identity_authorization') ? 403 : 428 });
});
test('unknown roles, missing versions and unavailable storage have no permissive fallback', async () => {
  await expect(store.get('__proto__',actor)).rejects.toMatchObject({ status: 400 });
  await expect(store.change(row.role,undefined,input,actor)).rejects.toMatchObject({ status: 428 });
  database.query.mockRejectedValue(new Error('offline'));
  await expect(store.get(row.role,actor)).rejects.toThrow('offline');
});
test.each(['license-review-administrator','license-reviewer'])('license review writer %s keeps its fixed fresh-MFA minimum even for global administration', async role => {
  row = { role,version: '1',mfa_required: true,max_age_seconds: 300 };
  expect(await store.get(role,actor)).toMatchObject({ locked: true });
  await expect(store.change(role,policyEtag(role,'1'),input,{ ...actor,roles: ['admin'] })).rejects.toMatchObject({ status: 409 });
});
test('aggregation uses every live canonical role and its durable policy version, not selected token scopes', async () => {
  const grants = ['license-manager','directory-reader'].map(role => ({ id:crypto.randomUUID(),role,policy_version:'1',activation_version:'1',activation_required:false,max_duration_seconds:28800 }));
  const policies = [{ role:'directory-reader',version:'1',mfa_required:true,max_age_seconds:900 },{ role:'license-manager',version:'2',mfa_required:true,max_age_seconds:300 }];
  const client = { query: jest.fn(async sql => ({ rows: sql.includes('FROM identity_company_activations') ? [] : sql.includes('FROM identity_role_assignments') ? grants : structuredClone(policies) })) };
  const first = await readRoleState(client,userId); expect(first.authentication).toEqual({ required:true,maxAgeSeconds:300 });
  policies[1].mfa_required = false; policies[1].version = '3';
  const relaxed = await readRoleState(client,userId); expect(relaxed.authentication.maxAgeSeconds).toBe(900);
  policies[1].mfa_required = true; policies[1].version = '4';
  expect((await readRoleState(client,userId)).rolesRevision).not.toBe(first.rolesRevision);
  expect(relaxed.rolesRevision).not.toBe(first.rolesRevision);
  policies.pop(); await expect(readRoleState(client,userId)).rejects.toThrow();
});
test('original bound assurance expires across all clients and ignores a refresh issue time', () => {
  expect(acceptsRoleAuthentication(input,actor)).toBe(false);
  const policy = { required:true,maxAgeSeconds:300 };
  expect(acceptsRoleAuthentication(policy,actor,actor.auth_time+299)).toBe(true);
  expect(acceptsRoleAuthentication(policy,{ ...actor,iat:actor.auth_time+301 },actor.auth_time+301)).toBe(false);
  expect(acceptsRoleAuthentication(policy,{ ...actor,mfa_authorization:{ ...actor.mfa_authorization,userId:crypto.randomUUID() } })).toBe(false);
});
