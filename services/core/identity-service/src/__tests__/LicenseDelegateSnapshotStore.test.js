'use strict';

jest.mock('../RoleState', () => ({ readRoleState: jest.fn() }));
const { readRoleState } = require('../RoleState');
const { LicenseDelegateSnapshotStore } = require('../LicenseDelegateSnapshotStore');
const {createHash}=require('crypto');
const userId = '11111111-1111-4111-8111-111111111111';
const viewer = { issuer: 'https://issuer.test', subject: 'canonical-operator' };
let client; let database; let store;
beforeEach(() => {
  jest.clearAllMocks();
  client = { query: jest.fn(async sql => ({ rows: sql.includes('SELECT user_id') ? [{ user_id: userId }] : [{ enabled: true, linked: true, eligibility_revision: '4',link_revision:'7' }] })) };
  database = { transaction: jest.fn(async operation => operation(client)) }; store = new LicenseDelegateSnapshotStore(database);
  readRoleState.mockResolvedValue({ delegationRevision: 'a'.repeat(64) });
});
test('a delegate reads only its canonical identity and minimal live authority evidence in a read-only transaction', async () => {
  expect(await store.snapshot(userId, viewer, false)).toEqual({ schemaVersion: 1, userId, revision: '4', enabled: true, linked: true, delegationRevision: createHash('sha256').update(JSON.stringify(['license-delegate-link-v1',viewer.issuer,'7','a'.repeat(64)])).digest('hex') });
  expect(database.transaction).toHaveBeenCalledWith(expect.any(Function), { readOnly: true });
  expect(client.query.mock.calls[0][1]).toEqual([viewer.issuer,viewer.subject]);
  expect(readRoleState).toHaveBeenCalledWith(client, userId, { delegateEvidence: true });
});
test('a scope configurator can read a known target without a directory profile grant', async () => {
  await store.snapshot(userId, viewer, true); expect(client.query).toHaveBeenCalledTimes(1);
  expect(client.query.mock.calls[0][1]).toEqual([userId,viewer.issuer]);
});
test('self lookup rejects a different canonical human before reading their authority', async () => {
  client.query.mockResolvedValueOnce({ rows: [] });
  await expect(store.snapshot(userId, viewer, false)).rejects.toMatchObject({ status: 403 }); expect(readRoleState).not.toHaveBeenCalled();
});
test.each([{ enabled: false, linked: true }, { enabled: true, linked: false }])('an unavailable canonical delegate has no role-source proof: %j', async state => {
  client.query.mockResolvedValue({ rows: [{ ...state, eligibility_revision: '5',link_revision:'7' }] });
  expect((await store.snapshot(userId, viewer, true)).delegationRevision).toBeNull();
});
test('unknown and noncanonical identities cannot be resolved through aliases', async () => {
  await expect(store.snapshot('alias', viewer, true)).rejects.toMatchObject({ status: 400 }); expect(client.query).not.toHaveBeenCalled();
  client.query.mockResolvedValue({ rows: [] }); await expect(store.snapshot(userId, viewer, true)).rejects.toMatchObject({ status: 404 });
});
test('a failed canonical read never substitutes old authority', async () => {
  readRoleState.mockRejectedValue(new Error('Owned store outage')); await expect(store.snapshot(userId, viewer, true)).rejects.toThrow('Owned store outage');
});
test('an issuer link replacement cannot revive a lease with the same canonical role grants',async()=>{const original=await store.snapshot(userId,viewer,true);client.query.mockResolvedValue({rows:[{enabled:true,linked:true,eligibility_revision:'4',link_revision:'8'}]});expect((await store.snapshot(userId,viewer,true)).delegationRevision).not.toBe(original.delegationRevision);});
test('missing canonical link evidence fails closed rather than returning a role-only hash',async()=>{client.query.mockResolvedValue({rows:[{enabled:true,linked:true,eligibility_revision:'4'}]});await expect(store.snapshot(userId,viewer,true)).rejects.toMatchObject({status:503});});
