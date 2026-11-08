'use strict';
const { ReleaseSync, sourceFor, parseRelease } = require('../catalog/releaseSync');
const brew = sourceFor('macos', { type: 'brew', id: 'firefox', cask: true });
const winget = sourceFor('windows', { type: 'winget', id: 'Mozilla.Firefox' });
test('only fixed provider hosts and literal safe package identifiers are resolved', () => {
  expect(brew.api).toBe('https://formulae.brew.sh/api/cask/firefox.json');
  expect(winget.api).toBe('https://api.github.com/repos/microsoft/winget-pkgs/contents/manifests/m/Mozilla/Firefox');
  for (const id of ['../secrets','https://evil.test','x?access_token=secret','x#foo','a/b','a%2fb']) expect(sourceFor('macos',{type:'brew',id})).toBeNull();
  expect(sourceFor('windows',{type:'url',id:'Mozilla.Firefox',url:'https://evil.test'})).toBeNull();
});
test('parses only verified identities and stable numeric versions; never guesses truncated GitHub results', () => {
  expect(parseRelease(brew,{token:'firefox',version:'100.2',homepage:'http://unsafe.test'})).toMatchObject({version:'100.2',homepage:null});
  expect(() => parseRelease(brew,{token:'different',version:'1'})).toThrow('identity');
  expect(parseRelease(winget,[{type:'dir',name:'9.1'},{type:'dir',name:'100.3'},{type:'dir',name:'101.0-beta'},{type:'file',name:'999.9'}])).toEqual({version:'100.3'});
  expect(() => parseRelease(winget,Array(1000).fill({type:'dir',name:'1.2'}))).toThrow('incomplete');
});
function fixture(metadata = {}, packages = {macos:{type:'brew',id:'firefox',cask:true}}) {
  const pool = {query:jest.fn(async sql => sql.startsWith('SELECT') ? {rows:[{id:'app1',name:'test',packages,metadata}]} : {rowCount:1,rows:[{id:'app1'}]})};
  return pool;
}
test('job has a stable id, coalesces concurrent refreshes and keeps completed evidence', async () => {
  let finish; const response = new Promise(resolve => {finish=resolve;}); const pool=fixture();
  const get=jest.fn(() => response); const sync = new ReleaseSync(pool,{get});
  const one=sync.sync(); const id=sync.status.id; const two=sync.sync(); expect(two).toBe(one); expect(sync.status.state).toBe('running');
  finish({data:{token:'firefox',version:'100.2'}}); await one;
  expect(sync.status).toMatchObject({id,state:'completed',completedApps:1,result:{confirmedSources:1,totalSources:1,partial:false}});
  expect(get.mock.calls[0][1]).toMatchObject({maxRedirects:0,timeout:8000});
  const [sql,params]=pool.query.mock.calls[1]; expect(sql).toContain('packages=$3::jsonb'); expect(sql).toContain("COALESCE(metadata->'catalogReleases'");
  expect(JSON.parse(params[1]).macos).toMatchObject({version:'100.2',packageId:'firefox',status:'confirmed'});
});
test('failure retains only a matching source version and its original timestamp', async () => {
  const previous={provider:'Homebrew',packageId:'firefox',version:'99.0',checkedAt:'2026-01-01T00:00:00Z'};
  const pool=fixture({catalogReleases:{macos:previous}}); const sync=new ReleaseSync(pool,{get:jest.fn().mockRejectedValue(new Error('offline'))});
  await sync.sync(); const observation=JSON.parse(pool.query.mock.calls[1][1][1]).macos;
  expect(observation).toMatchObject({...previous,status:'stale'}); expect(sync.status.result.partial).toBe(true);
  const changed=fixture({catalogReleases:{macos:{...previous,packageId:'old-package'}}});
  await new ReleaseSync(changed,{get:jest.fn().mockRejectedValue(new Error('offline'))}).sync();
  expect(JSON.parse(changed.query.mock.calls[1][1][1]).macos).toMatchObject({status:'unavailable'});
  expect(JSON.parse(changed.query.mock.calls[1][1][1]).macos.version).toBeUndefined();
});
test('a concurrent package edit produces no successful stale job result', async () => {
  const pool=fixture(); pool.query.mockImplementation(async sql => sql.startsWith('SELECT') ? {rows:[{id:'app1',name:'test',packages:{macos:{type:'brew',id:'firefox',cask:true}}}]} : {rowCount:0});
  const sync=new ReleaseSync(pool,{get:async()=>({data:{token:'firefox',version:'100.2'}})});
  await expect(sync.sync()).rejects.toThrow('binding_changed'); expect(sync.status.state).toBe('failed');
});
