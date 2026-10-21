'use strict';

const { GroupSnapshotClient, normalizeSnapshot, normalizeUserSnapshot } = require('../GroupSnapshotClient');
const groupId = '11111111-1111-4111-8111-111111111111';
const userId = '22222222-2222-4222-8222-222222222222';
const{groupSnapshot}=require('../../../../../../scripts/lib/group-license-snapshot-fixture.cjs');
const snapshot=groupSnapshot({groupId,name:'Engineering',revision:'42',memberIds:[userId]});
const snapshotHeaders = { 'X-OD-License-Snapshot-Protocol': '1' };
test('company snapshots use the independent owner endpoint with the original bearer',async()=>{
 const fetchImpl=jest.fn(async()=>new Response(JSON.stringify(snapshot),{headers:snapshotHeaders}));
 await new GroupSnapshotClient({baseUrl:'https://identity.test',fetchImpl}).snapshot(groupId,'Bearer original',true);
 expect(fetchImpl.mock.calls[0][0].pathname).toBe('/api/identity/company-license-groups/'+groupId+'/snapshot');
 expect(fetchImpl.mock.calls[0][1].headers).toEqual({Authorization:'Bearer original'});
});
const consent={grantId:'33333333-3333-4333-8333-333333333333',version:'1',issuer:'https://identity.test',clientId:'group-worker',clientRevision:'2',expiresAt:new Date(Date.parse(snapshot.observedAt)+60000).toISOString()};
test('source-consent metadata is separate from the stable canonical content hash and preserves the original v2 hash representation',()=>{
 const human=normalizeSnapshot(snapshot,groupId);const workload=normalizeSnapshot({...snapshot,sourceAuthorization:consent},groupId);expect(workload.hash).toBe(human.hash);expect(workload.sourceAuthorization).toEqual(consent);expect(workload.schemaVersion).toBe(3);
 const legacy={schemaVersion:2,unresolvedMemberIds:[],groupId,revision:undefined,deleted:false,name:'Engineering',memberIds:[userId],inactiveMemberIds:[],memberships:snapshot.memberships};expect(human.hash).toBe(require('node:crypto').createHash('sha256').update(JSON.stringify(legacy)).digest('hex'));
});
test.each([undefined,{}, {...consent,grantId:'legacy'},{...consent,version:'0'},{...consent,clientRevision:'9223372036854775808'},{...consent,clientId:'bad/client'},{...consent,issuer:''},{...consent,expiresAt:snapshot.observedAt},{...consent,extra:true}])('an incomplete or contradictory source authorization cannot renew a lease: %j',sourceAuthorization=>{
 expect(()=>normalizeSnapshot({...snapshot,sourceAuthorization},groupId)).toThrow();
});
test('a workload source frame cannot borrow a canonical human viewer or the retired v2 transport shape',()=>{
 expect(()=>normalizeSnapshot({...snapshot,sourceAuthorization:consent,viewerUserId:userId,viewerEnabled:true},groupId)).toThrow();expect(()=>normalizeSnapshot({...snapshot,schemaVersion:2},groupId)).toThrow();
});
test('an already expired known consent is rejected even while the five-minute observation horizon is still open',async()=>{
 const old=groupSnapshot({groupId,memberIds:[userId]},{now:Date.now()-120000});const value={...old,sourceAuthorization:{...consent,expiresAt:new Date(Date.now()-60000).toISOString()}};
 await expect(new GroupSnapshotClient({fetchImpl:async()=>new Response(JSON.stringify(value),{headers:snapshotHeaders})}).snapshot(groupId,'Bearer workload')).rejects.toMatchObject({status:503});
});
test.each([
 {schemaVersion:1},{observedAt:undefined},{validUntil:undefined},{memberships:undefined},{memberships:[]},
 {observedAt:'not-a-time'},{validUntil:new Date(Date.parse(snapshot.validUntil)+1000).toISOString()},
 {memberships:[{...snapshot.memberships[0],membershipId:'legacy'}]},
 {memberships:[{...snapshot.memberships[0],membershipId:snapshot.memberships[0].membershipId.toUpperCase().replace('4','A')}]},
 {memberships:[{...snapshot.memberships[0],eligibilityRevision:'0'}]},
 {memberships:[{...snapshot.memberships[0],eligibilityRevision:'9223372036854775808'}]},
 {memberships:[{...snapshot.memberships[0],reviewDeadlineAt:snapshot.observedAt}]},
 {memberships:[{...snapshot.memberships[0],extra:true}]},{hash:'a'.repeat(64)},{unexpected:true},
])('unbounded, legacy or incarnation-free group evidence fails closed: %j',change=>{
 expect(()=>normalizeSnapshot({...snapshot,...change},groupId)).toThrow();
});
test('observation renewal preserves the stable content hash but incarnation or review deadline changes do not',()=>{
 const first=normalizeSnapshot(snapshot,groupId);const later=groupSnapshot({...snapshot},{now:Date.parse(snapshot.observedAt)+1000});
 expect(normalizeSnapshot(later,groupId).hash).toBe(first.hash);
 for(const change of [{membershipId:groupId},{eligibilityRevision:'2'},{reviewDeadlineAt:new Date(Date.parse(snapshot.observedAt)+60000).toISOString()}]){
 expect(normalizeSnapshot({...snapshot,memberships:[{...snapshot.memberships[0],...change}]},groupId).hash).not.toBe(first.hash);
 }
});
test.each([-301000,6000])('transport rejects expired or future observations without a cached-positive fallback: %d',async offset=>{
 const stale=groupSnapshot({groupId,memberIds:[userId]},{now:Date.now()+offset});const client=new GroupSnapshotClient({fetchImpl:async()=>new Response(JSON.stringify(stale),{headers:snapshotHeaders})});
 await expect(client.snapshot(groupId,'Bearer original')).rejects.toMatchObject({status:503});
});
test('the bounded group transport supports a complete ten-thousand-member v2 proof, while other identity endpoints remain smaller',async()=>{
 const identifiers=Array.from({length:10000},(_,index)=>'00000000-0000-4000-8000-'+String(index).padStart(12,'0'));const complete=groupSnapshot({groupId,memberIds:identifiers});
 complete.memberships=complete.memberships.map(member=>({...member,eligibilityRevision:'9007199254740993',reviewDeadlineAt:new Date(Date.now()+60000).toISOString()}));
 const encoded=JSON.stringify(complete);expect(Buffer.byteLength(encoded)).toBeGreaterThan(2*1024*1024);expect(Buffer.byteLength(encoded)).toBeLessThan(4*1024*1024);
 const client=new GroupSnapshotClient({fetchImpl:async()=>new Response(encoded,{headers:snapshotHeaders})});expect((await client.snapshot(groupId,'Bearer original')).memberIds).toHaveLength(10000);
 await expect(client.subject('Bearer original',expected)).rejects.toMatchObject({status:503});
 const oversized=new GroupSnapshotClient({fetchImpl:async()=>new Response('x'.repeat(4*1024*1024+1),{headers:snapshotHeaders})});await expect(oversized.snapshot(groupId,'Bearer original')).rejects.toMatchObject({status:503});
});
const binding = { schemaVersion: 1, issuer: 'https://identity.test', subject: 'verified-alias', userId, enabled: true };
const expected = { issuer: binding.issuer, subject: binding.subject };
const userSnapshot = { schemaVersion: 1, userId, revision: '9007199254740993', enabled: true, deleted: false };
const reviewer = { schemaVersion: 1, userId, enabled: true, linked: true, canReview: true };
describe.each([
  ['snapshot', groupId, snapshot],
  ['user', userId, userSnapshot],
  ['reviewer', userId, reviewer],
  ['scopeReviewer', userId, reviewer],
  ['activationReviewer', userId, { schemaVersion: 1, userId, revision: '3', enabled: true, linked: true, reviewRevision: 'b'.repeat(64) }],
  ['delegate', userId, { schemaVersion: 1, userId, revision: '2', enabled: true, linked: true, delegationRevision: 'a'.repeat(64) }],
])('%s HTTP snapshot protocol', (method, id, value) => {
  test.each([undefined, '2'])('rejects protocol %j on a fresh bearer after a valid response', async protocol => {
    const headers = protocol === undefined ? {} : { 'X-OD-License-Snapshot-Protocol': protocol };
    const fetchImpl = jest.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(value), { headers: snapshotHeaders }))
      .mockResolvedValueOnce(new Response(JSON.stringify(value), { headers }));
    const client = new GroupSnapshotClient({ fetchImpl });
    await expect(client[method](id, 'Bearer original')).resolves.toMatchObject(value);
    await expect(client[method](id, 'Bearer fresh')).rejects.toMatchObject({ status: 503, message: 'Tenant-bound identity snapshot receiver required' });
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    expect(fetchImpl.mock.calls.map(([, options]) => options.headers.Authorization)).toEqual(['Bearer original', 'Bearer fresh']);
  });

  test('preserves a headerless 404 with a fresh bearer and reads again without cached evidence', async () => {
    const fetchImpl = jest.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(value), { headers: snapshotHeaders }))
      .mockResolvedValueOnce(new Response('{}', { status: 404 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(value), { headers: snapshotHeaders }));
    const client = new GroupSnapshotClient({ fetchImpl });
    await expect(client[method](id, 'Bearer original')).resolves.toMatchObject(value);
    await expect(client[method](id, 'Bearer fresh')).rejects.toMatchObject({ status: 404 });
    await expect(client[method](id, 'Bearer renewed')).resolves.toMatchObject(value);
    expect(fetchImpl).toHaveBeenCalledTimes(3);
    expect(fetchImpl.mock.calls.map(([, options]) => options.headers.Authorization)).toEqual(['Bearer original', 'Bearer fresh', 'Bearer renewed']);
  });
});
test('scope activation reviewer proof uses its fixed endpoint and the original human credential',async()=>{
 const value={schemaVersion:1,userId,revision:'3',enabled:true,linked:true,reviewRevision:'b'.repeat(64)};const fetchImpl=jest.fn(async()=>new Response(JSON.stringify(value),{headers:snapshotHeaders}));
 expect(await new GroupSnapshotClient({baseUrl:'https://identity.test',fetchImpl}).activationReviewer(userId,'Bearer operator')).toEqual(value);
 expect(String(fetchImpl.mock.calls[0][0])).toBe('https://identity.test/api/license-activation-reviewers/'+userId+'/snapshot');expect(fetchImpl.mock.calls[0][1].headers.Authorization).toBe('Bearer operator');
});
test.each([{userId:groupId},{revision:'0'},{revision:'9223372036854775808'},{enabled:false},{linked:false},{reviewRevision:'bad'},{canReview:true}])('scope reviewer proof rejects malformed or contradictory origin: %j',async change=>{
 const value={schemaVersion:1,userId,revision:'3',enabled:true,linked:true,reviewRevision:'b'.repeat(64),...change};await expect(new GroupSnapshotClient({fetchImpl:async()=>new Response(JSON.stringify(value),{headers:snapshotHeaders})}).activationReviewer(userId,'Bearer operator')).rejects.toMatchObject({status:503});
});

test('delegate evidence uses the fixed endpoint and only the original operator bearer', async () => {
  const value = { schemaVersion: 1, userId, revision: '2', enabled: true, linked: true, delegationRevision: 'a'.repeat(64) };
  const fetchImpl = jest.fn(async () => new Response(JSON.stringify(value), { headers: snapshotHeaders })); const client = new GroupSnapshotClient({ baseUrl: 'https://identity.test', fetchImpl });
  expect(await client.delegate(userId, 'Bearer original')).toEqual(value);
  expect(String(fetchImpl.mock.calls[0][0])).toBe('https://identity.test/api/license-delegates/'+userId+'/snapshot');
  expect(fetchImpl.mock.calls[0][1].headers.Authorization).toBe('Bearer original');
});
test.each([{userId:groupId},{revision:'0'},{revision:'9223372036854775808'},{delegationRevision:'bad'},{enabled:false},{linked:false},{extra:true},{schemaVersion:2}])('delegate evidence rejects malformed or contradictory authority: %j', async change => {
  const value = { schemaVersion: 1, userId, revision: '2', enabled: true, linked: true, delegationRevision: 'a'.repeat(64), ...change };
  await expect(new GroupSnapshotClient({ fetchImpl: async () => new Response(JSON.stringify(value), { headers: snapshotHeaders }) }).delegate(userId,'Bearer original')).rejects.toMatchObject({status:503});
});
test('absent original authority cannot use an ambient token for a delegate snapshot', async () => {
  const fetchImpl = jest.fn(); await expect(new GroupSnapshotClient({ fetchImpl }).delegate(userId,undefined)).rejects.toMatchObject({status:503}); expect(fetchImpl).not.toHaveBeenCalled();
});

test('reviewer availability uses only a fixed purpose-limited endpoint and the original credential', async () => {
  const fetchImpl = jest.fn(async () => new Response(JSON.stringify(reviewer), { headers: snapshotHeaders }));
  const client = new GroupSnapshotClient({ baseUrl: 'https://identity.test', fetchImpl });
  expect(await client.reviewer(userId, 'Bearer original')).toEqual(reviewer);
  expect(String(fetchImpl.mock.calls[0][0])).toBe(`https://identity.test/api/license-reviewers/${userId}/snapshot`);
  expect(fetchImpl.mock.calls[0][1]).toMatchObject({ headers: { Authorization: 'Bearer original' }, redirect: 'error', cache: 'no-store' });
});
test.each([null, {}, { ...reviewer, userId: groupId }, { ...reviewer, enabled: false }, { ...reviewer, linked: false },
  { ...reviewer, canReview: 'yes' }, { ...reviewer, roles: ['admin'] }])('malformed reviewer authority cannot configure a policy: %j', async value => {
  const client = new GroupSnapshotClient({ baseUrl: 'https://identity.test', fetchImpl: async () => new Response(JSON.stringify(value), { headers: snapshotHeaders }) });
  await expect(client.reviewer(userId, 'Bearer original')).rejects.toMatchObject({ status: 503 });
});

test.each([null, {}, { ...userSnapshot, userId: groupId }, { ...userSnapshot, revision: 42 }, { ...userSnapshot, revision: '0' },
  { ...userSnapshot, revision: '9223372036854775808' }, { ...userSnapshot, enabled: 'true' }, { ...userSnapshot, deleted: true }])('rejects invalid eligibility evidence: %j', value => {
  expect(() => normalizeUserSnapshot(value, userId)).toThrow();
});

test('user eligibility uses a fixed bounded transport, not body-supplied status or a guessed subject', async () => {
  const fetchImpl = jest.fn(async () => new Response(JSON.stringify(userSnapshot), { headers: snapshotHeaders }));
  const client = new GroupSnapshotClient({ baseUrl: 'https://identity.test', fetchImpl });
  expect(await client.user(userId, 'Bearer original')).toEqual(userSnapshot);
  expect(String(fetchImpl.mock.calls[0][0])).toBe(`https://identity.test/api/license-users/${userId}/snapshot`);
  expect(fetchImpl.mock.calls[0][1]).toMatchObject({ headers: { Authorization: 'Bearer original' }, redirect: 'error', cache: 'no-store' });
  await expect(client.user('token-alias', 'Bearer original')).rejects.toMatchObject({ status: 400 });
});

test('self-binding forwards the original credential to a fixed path and requires the verified issuer/subject pair', async () => {
  const fetchImpl = jest.fn(async () => new Response(JSON.stringify(binding)));
  const client = new GroupSnapshotClient({ baseUrl: 'https://identity.test', fetchImpl });
  expect(await client.subject('Bearer operator', expected)).toEqual({ ...expected, userId, enabled: true });
  expect(String(fetchImpl.mock.calls[0][0])).toBe('https://identity.test/api/identity/subject');
  expect(fetchImpl.mock.calls[0][1]).toEqual(expect.objectContaining({ headers: { Authorization: 'Bearer operator' }, redirect: 'error', cache: 'no-store' }));
});

test.each([null, {}, { ...binding, subject: 'other' }, { ...binding, issuer: 'https://forged.test' }, { ...binding, userId: 'token-alias' },
  { ...binding, userId: 'AAAAAAAA-1111-4111-8111-111111111111' }, { ...binding, enabled: 'true' }, { ...binding, userId: null, enabled: false },
  { ...binding, schemaVersion: 2 }])('invalid self-binding cannot become a canonical principal: %j', async value => {
  const client = new GroupSnapshotClient({ fetchImpl: async () => new Response(JSON.stringify(value)) });
  await expect(client.subject('Bearer operator', expected)).rejects.toMatchObject({ status: 503 });
});

test('an authoritative missing link is distinguishable from a source outage or an obsolete endpoint', async () => {
  const client = new GroupSnapshotClient({ fetchImpl: async () => new Response(JSON.stringify({ ...binding, userId: null, enabled: null })) });
  expect(await client.subject('Bearer operator', expected)).toEqual({ ...expected, userId: null, enabled: null });
  for (const status of [404, 429, 503]) {
    const missing = new GroupSnapshotClient({ fetchImpl: async () => new Response('{}', { status }) });
    await expect(missing.subject('Bearer operator', expected)).rejects.toMatchObject({ status: 503 });
  }
});

test('oversized identity responses cannot allocate unbounded memory', async () => {
  const client = new GroupSnapshotClient({ fetchImpl: async () => new Response('x'.repeat(2 * 1024 * 1024 + 1)) });
  await expect(client.subject('Bearer operator', expected)).rejects.toMatchObject({ status: 503 });
});

test('forwards only the operator credential to the fixed source and refuses redirects', async () => {
  const fetchImpl = jest.fn(async () => new Response(JSON.stringify(snapshot), { headers: snapshotHeaders }));
  const client = new GroupSnapshotClient({ baseUrl: 'https://identity.test', fetchImpl });
  expect((await client.snapshot(groupId, 'Bearer verified-operator')).memberIds).toEqual([userId]);
  expect(String(fetchImpl.mock.calls[0][0])).toBe(`https://identity.test/api/license-groups/${groupId}/snapshot`);
  expect(fetchImpl.mock.calls[0][1]).toEqual(expect.objectContaining({ headers: { Authorization: 'Bearer verified-operator' }, redirect: 'error' }));
});
test('administrative reviewer discovery is minimal, role-specific and original-bearer only',async()=>{
 const fetchImpl=jest.fn(async()=>new Response(JSON.stringify(reviewer),{headers:snapshotHeaders}));const client=new GroupSnapshotClient({baseUrl:'https://identity.test',fetchImpl});
 expect(await client.scopeReviewer(userId,'Bearer original')).toEqual(reviewer);expect(String(fetchImpl.mock.calls[0][0])).toBe(`https://identity.test/api/license-scope-reviewers/${userId}/snapshot`);
 expect(fetchImpl.mock.calls[0][1]).toMatchObject({headers:{Authorization:'Bearer original'},redirect:'error',cache:'no-store'});
});
test.each([null,{...reviewer,userId:groupId},{...reviewer,enabled:false},{...reviewer,linked:false},{...reviewer,canReview:'yes'},{...reviewer,roles:['admin']}])('malformed administrative voter evidence fails closed: %j',async value=>{
 const client=new GroupSnapshotClient({fetchImpl:async()=>new Response(JSON.stringify(value),{headers:snapshotHeaders})});await expect(client.scopeReviewer(userId,'Bearer original')).rejects.toMatchObject({status:503});
});

test.each([null, {}, { ...snapshot, revision: 42 }, { ...snapshot, revision: '9223372036854775808' }, { ...snapshot, memberIds: [userId, userId] },
  { ...snapshot, inactiveMemberIds: [userId] }, { ...snapshot, deleted: true }, { ...snapshot, unresolvedMemberIds: ['unknown'] }, { ...snapshot, viewerUserId: 'forged', viewerEnabled: true }])('rejects incomplete, conflicting or unresolved source input: %j', value => {
  expect(() => normalizeSnapshot(value, groupId)).toThrow();
});

test.each([401, 403, 404, 429, 500, 503])('source HTTP %s never becomes an empty group', async status => {
  const client = new GroupSnapshotClient({ fetchImpl: async () => new Response('{}', { status }) });
  await expect(client.snapshot(groupId, 'Bearer operator')).rejects.toMatchObject({ status: status === 401 || status === 403 ? 403 : status === 404 ? 404 : 503 });
});

test('viewer identity is bound separately and never changes the group fingerprint', () => {
  const first = normalizeSnapshot({ ...snapshot, viewerUserId: userId, viewerEnabled: true }, groupId);
  const second = normalizeSnapshot(snapshot, groupId);
  expect(first.hash).toBe(second.hash);
  expect(first.viewerUserId).toBe(userId);
  expect(second.viewerUserId).toBeNull();
});

test.each(['Bearer token\r\nforged', '', undefined])('invalid credentials cannot trigger a fallback service token: %j', async authorization => {
  const fetchImpl = jest.fn();
  await expect(new GroupSnapshotClient({ fetchImpl }).snapshot(groupId, authorization)).rejects.toMatchObject({ status: 503 });
  expect(fetchImpl).not.toHaveBeenCalled();
});

test.each(['file:///tmp/snapshot', 'https://identity.test/redirect', 'https://user:secret@identity.test', 'https://identity.test/?target=other'])('rejects unsafe source configurations: %s', baseUrl => {
  expect(() => new GroupSnapshotClient({ baseUrl })).toThrow();
});
