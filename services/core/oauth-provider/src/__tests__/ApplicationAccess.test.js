'use strict';
const { randomUUID } = require('node:crypto');
const { ApplicationAccess,validApplicationContext } = require('../ApplicationAccess');
const { permissionsOf } = require('../ClientRegistry');
const { argumentsForBootstrap } = require('../../scripts/bootstrap-application-access');
const context = { userId: randomUUID(),revision: '1',linkRevision: '1',rolesRevision: 'a'.repeat(64) };
const actor = { iss: 'https://issuer.test',sub: 'verified',actor_type: 'user',client_id: 'console',identity_authorization: context,roles: ['application-access-administrator'] };
const input = extra => ({ requestId: randomUUID(),targetType: 'user',targetId: randomUUID(),durationSeconds: 3600,reason: 'Reviewed application access',...extra });
let access;
beforeEach(() => { access = new ApplicationAccess({ isAvailable: () => false },{ identity: { target: jest.fn() } }); });
test('assignment staff is separate from metadata, secrets, license and directory administration', () => {
  expect(permissionsOf(actor)).toEqual(['applications.assignments.read','applications.assignments.manage']);
  expect(permissionsOf({ ...actor,roles: ['application-access-reader'] })).toEqual(['applications.assignments.read']);
  expect(permissionsOf({ ...actor,roles: ['application-administrator'] })).not.toContain('applications.assignments.manage');
});
test.each(['user','application-reader','application-administrator','license-administrator','session-administrator'])('%s cannot manufacture assignment authority', async role => {
  await expect(access.grant('app',input(),{ ...actor,roles: [role] })).rejects.toMatchObject({ status: 403 });
});
test('workload role labels, arbitrary scopes and missing canonical identities never manage human access', async () => {
  for (const invalid of [{ ...actor,actor_type: 'application',roles: ['admin'] },{ ...actor,roles: [],scope: 'oauth.admin' },{ ...actor,identity_authorization: undefined }]) await expect(access.grant('app',input(),invalid)).rejects.toMatchObject({ status: 403 });
});
test.each([{ targetType: 'role' },{ targetId: 'alice' },{ durationSeconds: 0 },{ durationSeconds: 2592001 },{ durationSeconds: '3600' },{ requestId: 'same' },{ reason: 'short' },{ reason: 'x'.repeat(501) },{ approved: true },{ actor: 'forged' },{ expiresAt: '2099-01-01' }])('invalid or privileged input cannot create a grant: %j', async override => {
  await expect(access.grant('app',input(override),actor)).rejects.toMatchObject({ status: 400 });
  expect(access.identity.target).not.toHaveBeenCalled();
});
test('client authorization is checked before probing another canonical target', async () => {
  await expect(access.grant('app',input(),actor)).rejects.toMatchObject({ status: 503 }); expect(access.identity.target).not.toHaveBeenCalled();
});
test('no administrator bypass exists for user sign-in and legacy token contexts are not upgraded', async () => {
  access.transaction = jest.fn(async operation => operation({ effective: async () => [] }));
  await expect(access.context('app',{ context,memberships: [],authorization: { roles: ['admin'] } })).rejects.toMatchObject({ status: 403 });
  expect(await access.matches('app',{ context,memberships: [] },undefined)).toBe(false);
});
test('membership incarnation and grant UUIDs fence remove/readd and regrant without global client generation changes', async () => {
  const groupId = randomUUID(); const grant = { id: randomUUID(),target_type: 'group',target_id: groupId };
  access.transaction = jest.fn(async operation => operation({ effective: async (_id,_user,groups) => groups.includes(groupId) ? [grant] : [] }));
  const state = { context,memberships: [{ groupId,membershipId: randomUUID() }] }; const original = await access.context('app',state);
  expect(await access.matches('app',state,original)).toBe(true);
  expect(await access.matches('app',{ context,memberships: [] },original)).toBe(false);
  expect(await access.matches('app',{ context,memberships: [{ groupId,membershipId: randomUUID() }] },original)).toBe(false);
  grant.id = randomUUID(); expect(await access.matches('app',state,original)).toBe(false);
});
test.each([undefined,{ schemaVersion: 1,clientId: 'app',userId: context.userId,revision: 'old' },{ schemaVersion: 1,clientId: 'app',userId: context.userId,revision: 'a'.repeat(64),extra: true }])('an incomplete or overbroad application context cannot match: %j', value => {
  expect(validApplicationContext(value)).toBe(false);
});
test('explicit demo protocol bypass is never a production or management fallback', async () => {
  expect(() => new ApplicationAccess({}, { demo: true,production: true })).toThrow();
  const demo = new ApplicationAccess({}, { demo: true,production: false }); expect(await demo.matches('app',{},undefined)).toBe(true);
  await expect(demo.grant('app',input(),{ ...actor,identity_authorization: undefined })).rejects.toMatchObject({ status: 403 });
});
test.each([['app',context.userId,'--permanent','Reviewed recovery'],['app','username','60','Reviewed recovery'],['app',context.userId,'28801','Reviewed recovery']])('offline recovery rejects unbounded/guessed inputs: %j', args => {
  expect(() => argumentsForBootstrap(args)).toThrow();
});
test('offline recovery is an explicit canonical, bounded, reasoned grant', () => {
  expect(argumentsForBootstrap(['web-app',context.userId,'3600','Reviewed recovery access'])).toEqual({ clientId: 'web-app',userId: context.userId,durationSeconds: 3600,reason: 'Reviewed recovery access' });
});
test('a durable company owner source grants only the configured console and never bypasses unknown or revoked evidence', async () => {
  const identity = { companyConsole: jest.fn(async () => ({ active: true, revision: 'b'.repeat(64) })) };
  const current = new ApplicationAccess({}, { identity, companyConsoleClientId: 'web-app' }); current.transaction = jest.fn(async operation => operation({ effective: async () => [] }));
  const state = { context, memberships: [] }; expect(await current.context('web-app', state)).toEqual({ schemaVersion: 1, clientId: 'web-app', userId: context.userId, revision: 'b'.repeat(64) });
  await expect(current.context('other-client', state)).rejects.toMatchObject({ status: 403 }); expect(identity.companyConsole).toHaveBeenCalledTimes(1);
  identity.companyConsole.mockResolvedValueOnce({ active: false, revision: null }); await expect(current.context('web-app', state)).rejects.toMatchObject({ status: 403 });
  identity.companyConsole.mockRejectedValueOnce(new Error('source unavailable')); await expect(current.context('web-app', state)).rejects.toThrow('source unavailable');
});
