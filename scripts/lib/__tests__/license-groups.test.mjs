import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { createGroupClient } from '../license-groups.mjs';
const id = n => '00000000-0000-4000-8000-' + String(n).padStart(12, '0');
const context = { schemaVersion: 1, companyLicenseGroupsProtocol: 1, actorUserId: id(1), tenantId: id(2), allocationMode: 'local-only' };
const reason = 'Automated group license allocation';
const fixture = () => ({ id: id(3), groupId: id(4), poolId: id(5), blueprintId: id(6), tenantId: id(2), status: 'active', revision: '1' });
let calls, linked, current, client, mode;
beforeEach(() => {
  calls = []; linked = fixture(); current = { id: id(4), name: 'Engineering', members: [], revision: '1' }; mode = '';
  client = createGroupClient({ request: async (method, path, body, options) => {
    calls.push({ method, path, body, options }); assert.equal(options.administrative, true);
    if (path === '/api/identity/access') return { status: 200, data: { userId: id(1), permissions: ['groups.create', 'groups.read', 'groups.members.manage'], companyOwner: true,
      demoMode: false, directoryCreationProtocol: 1, directoryReadProtocol: 1, directoryGroupMutationProtocol: 1 } };
    if (path === '/api/groups' && method === 'POST') return { status: 201, data: { ...current, name: body.name } };
    if (path === '/api/groups/' + id(4)) return { status: 200, data: current, etag: '"group-' + id(4) + '-1"' };
    if (path.includes('/members')) { current = { ...current, revision: '2', members: method === 'POST' ? [body.userId] : [] }; return { status: 200, data: current }; }
    if (method === 'GET' && path.includes('/preview')) return { status: 200, etag: '"company-license-group-' + linked.id + '-' + linked.revision + '"', data: { ...context, rule: linked, groupRevision: linked.status === 'active' ? '1' : null } };
    if (method === 'GET') return { status: 200, data: { ...context, rules: [linked], truncated: mode === 'truncated' } };
    if (path.endsWith('/unlink')) { linked = { ...linked, status: 'unlinked', revision: '2' }; return { status: 200, data: { ...context, rule: linked } }; }
    if (path.endsWith('/sync')) {
      const row = { userId: id(body.cursor ? 8 : 7), status: mode === 'blocked' ? 'blocked' : linked.status === 'unlinked' ? 'removed' : 'assigned', code: mode === 'blocked' ? 409 : null };
      return { status: 200, data: { ...context, actorUserId: mode === 'other-actor' ? id(99) : id(1), rule: linked, groupRevision: body.groupRevision,
        results: [row], nextCursor: mode === 'pages' && body.cursor === null ? row.userId : mode === 'stuck' ? id(9) : null, hasBlocked: mode === 'blocked' } };
    }
    return { status: 201, data: { ...context, rule: linked } };
  } });
});
test('creates an ordinary empty group with the original human and no license write', async () => {
  assert.equal((await client.create('Engineering')).name, 'Engineering'); assert.equal(calls.filter(call => call.method !== 'GET').length, 1);
});
test('link captures own context, uses a stable operation key and reconciles the linked rule', async () => {
  const result = await client.linkPool(id(4), id(5), reason, id(10)); assert.equal(result.hasBlocked, false);
  assert.deepEqual(calls.find(call => call.method === 'POST').options, { administrative: true, operationId: id(10) });
  assert.equal(result.rule.poolId, id(5)); assert.equal(result.results[0].status, 'assigned');
});
test('group membership uses exact ETag and follows with license sync', async () => {
  const result = await client.member('add', id(4), id(7)); assert.equal(result.membershipConfirmed, true);
  assert.equal(result.licenses.length, 1); assert.equal(calls.find(call => call.path.endsWith('/members')).options.etag, '"group-' + id(4) + '-1"');
  assert.equal(calls.at(-1).path.endsWith('/sync'), true);
});
test('unlink pins the current rule ETag before source cleanup', async () => {
  const result = await client.unlink(id(3), reason); assert.equal(result.rule.status, 'unlinked'); assert.equal(result.results[0].status, 'removed');
  assert.equal(calls.find(call => call.path.endsWith('/unlink')).options.etag, '"company-license-group-' + id(3) + '-1"');
});
test('walks explicit cursors and reports blocked allocation separately', async () => {
  mode = 'pages'; const result = await client.sync(id(3), reason); assert.equal(result.results.length, 2);
  mode = 'blocked'; assert.equal((await client.sync(id(3), reason)).hasBlocked, true);
});
test('never repeats a membership write after a later unconfirmed allocation', async () => {
  mode = 'other-actor'; await assert.rejects(client.member('add', id(4), id(7))); assert.deepEqual(current.members, [id(7)]);
  assert.equal(calls.filter(call => call.path.endsWith('/members')).length, 1);
});
test('rejects malformed selectors, foreign responses and nonadvancing cursors', async () => {
  await assert.rejects(client.linkPool('foreign', id(5), reason)); assert.equal(calls.length, 0);
  mode = 'other-actor'; await assert.rejects(client.sync(id(3), reason));
  mode = 'stuck'; await assert.rejects(client.sync(id(3), reason));
  mode = 'truncated'; await assert.rejects(client.list(id(4)));
});
test('the shipped CLI links through real HTTP using the human bearer and exits 2 on confirmed pool shortage', async () => {
  const {default:http}=await import('node:http');const {execFile}=await import('node:child_process');const {promisify}=await import('node:util');
  const {fileURLToPath}=await import('node:url');const calls=[];const fixtureRule=fixture();
  const server=http.createServer(async(req,res)=>{
    let body='';for await(const chunk of req)body+=chunk;calls.push({path:req.url,method:req.method,authorization:req.headers.authorization,operationId:req.headers['idempotency-key']});
    res.setHeader('Content-Type','application/json');
    if(req.method==='GET'&&req.url.includes('/preview')){res.setHeader('ETag','"company-license-group-'+id(3)+'-1"');return res.end(JSON.stringify({...context,rule:fixtureRule,groupRevision:'1'}));}
    if(req.method==='GET')return res.end(JSON.stringify({...context,rules:[],truncated:false}));
    if(req.url.endsWith('/sync'))return res.end(JSON.stringify({...context,rule:fixtureRule,groupRevision:'1',results:[{userId:id(7),status:'blocked',code:409}],nextCursor:null,hasBlocked:true}));
    res.statusCode=201;res.end(JSON.stringify({...context,rule:fixtureRule}));
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const origin='http://127.0.0.1:'+server.address().port;
  try{
    let outcome;try{await promisify(execFile)(process.execPath,[fileURLToPath(new URL('../../od.mjs',import.meta.url)),'license-group','link',id(4),id(5),reason],{env:{...process.env,OPENDIRECTORY_ISSUER:origin,OPENDIRECTORY_API_URL:origin,OPENDIRECTORY_ADMIN_ACCESS_TOKEN:'original-human'}});}catch(error){outcome=error;}
    assert.equal(outcome?.code,2);assert.equal(JSON.parse(outcome.stdout).hasBlocked,true);assert.equal(outcome.stderr,'');
    assert.equal(calls.every(call=>call.authorization==='Bearer original-human'),true);assert.match(calls.find(call=>call.method==='POST').operationId,/^[a-f0-9-]{36}$/);
    assert.equal(calls.some(call=>call.path==='/oauth/token'),false);
  }finally{await new Promise(resolve=>server.close(resolve));}
});
