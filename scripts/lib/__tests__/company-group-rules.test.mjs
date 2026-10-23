import {test} from 'node:test';import assert from 'node:assert/strict';import {createGroupRuleClient} from '../company-group-rules.mjs';import http from 'node:http';import {execFile} from 'node:child_process';import {promisify} from 'node:util';import {fileURLToPath} from 'node:url';
const id=n=>'00000000-0000-4000-8000-'+String(n).padStart(12,'0');const base={schemaVersion:1,companyGroupRuleProtocol:1,actorUserId:id(1),tenantId:id(2),groupId:id(3)};
const rule={groupId:id(3),tenantId:id(2),revision:'1',enabled:true,draft:{dynamic:{all:[{attribute:'department',operator:'equals',value:'Engineering'}]},childGroupIds:[],excludedUserIds:[]}};
const page={...base,rule,etag:`"group-rule-${id(3)}-1"`,executionMode:'manual'};
test('rule configuration preserves the human bearer purpose, exact version and immutable operation key',async()=>{
 const calls=[];const client=createGroupRuleClient({request:async(...args)=>{calls.push(args);return args[0]==='GET'?{status:200,data:page,etag:page.etag}:{status:200,etag:`"group-rule-${id(3)}-2"`,data:{...base,outcome:'applied',rule:{...rule,revision:'2'}}};}});
 await client.configure(id(3),{draft:rule.draft,enabled:true,reason:'Explicit own group-rule configuration',confirm:true});assert.equal(calls[0][3].administrative,true);assert.equal(calls[1][3].administrative,true);assert.equal(calls[1][3].etag,page.etag);assert.match(calls[1][3].operationId,/^[a-f0-9-]{36}$/);
});
test('the actual CLI sync emits confirmed pending review and exits 2 without acquiring an app token',async()=>{
 const server=http.createServer(async(req,res)=>{const chunks=[];for await(const chunk of req)chunks.push(chunk);assert.equal(req.headers.authorization,'Bearer original-human');res.setHeader('Content-Type','application/json');
  if(req.url.endsWith('/rule')){res.setHeader('ETag',page.etag);return res.end(JSON.stringify(page));}
  if(req.url.endsWith('/preview'))return res.end(JSON.stringify({...base,ruleRevision:'1',executionMode:'manual',observation:'a'.repeat(64),desired:[{userId:id(4),eligibilityRevision:'1'}],existing:[]}));
  assert.ok(req.url.endsWith('/sync'));assert.equal(JSON.parse(Buffer.concat(chunks)).confirm,true);res.end(JSON.stringify({...base,ruleRevision:'1',observation:'a'.repeat(64),results:[{userId:id(4),status:'awaiting-review',code:null}],nextCursor:null,hasBlocked:false}));
 });await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const origin='http://127.0.0.1:'+server.address().port;
 try{await assert.rejects(promisify(execFile)(process.execPath,[fileURLToPath(new URL('../../od.mjs',import.meta.url)),'group-rule','sync',id(3),'Actual independently reviewed group membership'],{env:{...process.env,OPENDIRECTORY_ISSUER:origin,OPENDIRECTORY_API_URL:origin,OPENDIRECTORY_ADMIN_ACCESS_TOKEN:'original-human'}}),error=>error.code===2&&JSON.parse(error.stdout).requiresReview===true);}
 finally{await new Promise(resolve=>server.close(resolve));}
});
