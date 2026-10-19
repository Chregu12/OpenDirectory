'use strict';

const { GroupSnapshotStore } = require('../GroupSnapshotStore');
const groupId = '11111111-1111-4111-8111-111111111111';
test('a denied workload consent cannot lock or refresh an unrelated canonical group before authorization',async()=>{
 const query=jest.fn();const store=new GroupSnapshotStore({transaction:operation=>operation({query})});const authorize=jest.fn(async()=>{throw Object.assign(new Error('No group consent'),{status:403});});await expect(store.snapshot(groupId,null,{authorize})).rejects.toMatchObject({status:403});expect(query).not.toHaveBeenCalled();
});

test.each([[], [{ id: groupId, enabled: true }], [{ id: groupId, enabled: false }]].map(rows => [rows]))('self-binding reads only the verified issuer/subject in a read-only transaction: %j', rows => {
  const query = jest.fn().mockResolvedValue({ rows });
  const database = { transaction: jest.fn(operation => operation({ query })) };
  const viewer = { issuer: 'https://identity.test', subject: 'external-alias' };
  return new GroupSnapshotStore(database).subject(viewer).then(result => {
    expect(result).toEqual({ schemaVersion: 1, ...viewer, userId: rows[0]?.id || null, enabled: rows[0]?.enabled ?? null });
    expect(query).toHaveBeenCalledWith(expect.stringContaining('WHERE links.issuer=$1 AND links.subject=$2'), [viewer.issuer, viewer.subject]);
    expect(database.transaction).toHaveBeenCalledWith(expect.any(Function), { readOnly: true });
  });
});

test('a malformed group identifier cannot reach storage', async () => {
  const database = { transaction: jest.fn() };
  await expect(new GroupSnapshotStore(database).snapshot('not-a-group')).rejects.toMatchObject({ status: 400 });
  expect(database.transaction).not.toHaveBeenCalled();
});

test('oversized groups fail explicitly instead of returning a truncated allocation source', async () => {
  const query = jest.fn().mockResolvedValueOnce({rows:[]}).mockResolvedValueOnce({rows:[{observed_at:new Date()}]}).mockResolvedValueOnce({ rows: [{ id: groupId, revision: '9007199254740993' }] }).mockResolvedValueOnce({rows:[{coherent:true}]}).mockResolvedValueOnce({ rows: Array.from({ length: 10001 }, () => ({})) });
  const database = { transaction: jest.fn(async operation => operation({ query })) };
  await expect(new GroupSnapshotStore(database).snapshot(groupId)).rejects.toMatchObject({ status: 413 });
  expect(database.transaction).toHaveBeenCalledWith(expect.any(Function));
});

test('large revisions remain exact strings rather than imprecise JavaScript numbers', async () => {
  const query = jest.fn().mockResolvedValueOnce({rows:[]}).mockResolvedValueOnce({rows:[{observed_at:new Date()}]}).mockResolvedValueOnce({ rows: [{ id: groupId, revision: '9007199254740993' }] }).mockResolvedValueOnce({rows:[{coherent:true}]}).mockResolvedValueOnce({ rows: [] });
  const result = await new GroupSnapshotStore({ transaction: operation => operation({ query }) }).snapshot(groupId);
  expect(result.revision).toBe('9007199254740993');
});
test.each([false, undefined])('foreign or unavailable retained membership ownership cannot enter a source projection: %j', async coherent => {
  const query = jest.fn().mockResolvedValueOnce({ rows: [] }).mockResolvedValueOnce({ rows: [{ observed_at: new Date() }] }).mockResolvedValueOnce({ rows: [{ id: groupId, revision: '1' }] }).mockResolvedValueOnce({ rows: coherent === undefined ? [] : [{ coherent }] });
  await expect(new GroupSnapshotStore({ transaction: operation => operation({ query }) }).snapshot(groupId)).rejects.toMatchObject({ status: 503, message: 'Group contains foreign retained identities' });
  expect(query).toHaveBeenCalledTimes(4);
});
test('only explicitly effective reviewed members enter the license source, without reporting pending humans disabled globally',async()=>{
 const userId='22222222-2222-4222-8222-222222222222';const query=jest.fn().mockResolvedValueOnce({rows:[]}).mockResolvedValueOnce({rows:[{observed_at:new Date()}]}).mockResolvedValueOnce({rows:[{id:groupId,name:'Reviewed group',revision:'1'}]}).mockResolvedValueOnce({rows:[{coherent:true}]}).mockResolvedValueOnce({rows:[{id:userId,user_id:userId,enabled:true,review_allowed:false}]});
 const result=await new GroupSnapshotStore({transaction:operation=>operation({query})}).snapshot(groupId);expect(result.memberIds).toEqual([]);expect(result.inactiveMemberIds).toEqual([userId]);expect(query.mock.calls[0]).toEqual(['SELECT identity_membership_review_refresh($1)',[groupId]]);
});
