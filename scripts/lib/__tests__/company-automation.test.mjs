import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createAutomationClient, runAutomationWorker } from '../company-automation.mjs';
import { createClient } from '../opendirectory-client.mjs';
import http from 'node:http';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
const id = n => '00000000-0000-4000-8000-' + String(n).padStart(12, '0');
const response = (data, status = 200) => ({status,data:{schemaVersion:1,companyAutomationProtocol:1,principal:{kind:'application',clientId:'worker',clientRevision:'1'},...data}});
test('enrollment uses app credentials while approval and revocation use the original human token',async()=>{
 const calls=[];const client=createAutomationClient({request:async(...args)=>{
  calls.push(args);const body=args[2];const principal=args[3].administrative?{kind:'owner',userId:id(10),tenantId:id(11)}:{kind:'application',clientId:'worker',clientRevision:'1'};
  if(args[1].endsWith('/enrollments'))return response({...body,principal,clientId:'worker',clientRevision:'1',requestedScope:'company.automation',expiresAt:new Date(Date.now()+60000).toISOString()},201);
  return response({principal,grant:{...body,id:body.id||id(2),enrollmentId:body.enrollmentId||id(1),tenantId:id(11),clientId:'worker',clientRevision:'1',actions:['directory.users.export'],expiresAt:body.expiresAt||new Date(Date.now()+3600000).toISOString(),revision:body.confirm&&!body.id?'2':'1',status:body.confirm&&!body.id?'revoked':'active'}},body.id?201:200);
 }});
 await client.enroll('Export worker');assert.equal(calls[0][3].administrative,false);
 await client.approve(id(1),'worker','1',['directory.users.export']);assert.equal(calls[1][3].administrative,true);assert.equal(calls[1][2].confirm,true);
 await client.revoke(id(2),'1');assert.equal(calls[2][3].administrative,true);assert.equal(calls[2][3].etag,'"company-automation-grant-'+id(2)+'-1"');
});
test('an app worker performs actual runs without requesting a human token and supports once and a stopped signal',async()=>{
 let runs=0;const results=[];await runAutomationWorker({run:async()=>{runs++;return{job:{id:id(3),status:'succeeded'}};}},id(1),{once:true,onResult:result=>results.push(result)});
 assert.equal(runs,1);assert.equal(results[0].job.status,'succeeded');
 await runAutomationWorker({run:async()=>{throw new Error('Must not run');}},id(1),{signal:AbortSignal.abort()});
 await assert.rejects(runAutomationWorker({run:async()=>{throw Object.assign(new Error('Revoked'),{status:403});}},id(1)));
});
test('job inputs cannot expand the delegated dataset or accept arbitrary commands',async()=>{
 let calls=0;const client=createAutomationClient({request:async()=>{calls++;return response({},201);}});
 await assert.rejects(client.enqueue(id(1),'users.delete'));await assert.rejects(client.schedule(id(1),'directory.users.export',1));assert.equal(calls,0);
});
test('artifact download explicitly bounds large responses and verifies its actual content hash and job target',async()=>{
 const content='a'.repeat(1100000);const sha256=createHash('sha256').update(content).digest('hex');let options;
 const client=createAutomationClient({request:async(_method,_path,_body,value)=>{options=value;return response({jobId:id(1),content,sha256,contentType:'text/csv;charset=utf-8'});}});
 assert.equal((await client.result(id(1))).sha256,sha256);assert.equal(options.maxResponseBytes,32*1024*1024);
 await assert.rejects(createAutomationClient({request:async()=>response({jobId:id(2),content,sha256,contentType:'application/json'})}).result(id(1)));
 await assert.rejects(createAutomationClient({request:async()=>response({jobId:id(1),content:content+'tampered',sha256,contentType:'application/json'})}).result(id(1)));
});
test('unconfirmed run responses are not printed as successful jobs',async()=>{
 await assert.rejects(createAutomationClient({request:async()=>({status:202,data:{job:{status:'succeeded'}}})}).run(id(1)));
 assert.equal(await createAutomationClient({request:async()=>({status:204,data:null})}).run(id(1)),null);
});
test('the real CLI worker emits parseable JSON lines and a failed job retains exit code 2',async()=>{
 let status='succeeded';let runs=0;
 const server=http.createServer(async(req,res)=>{
  for await(const chunk of req){}res.setHeader('Content-Type','application/json');
  if(req.url==='/oauth/token')return res.end(JSON.stringify({access_token:'app-token',token_type:'Bearer',expires_in:60}));
  assert.equal(req.url,'/api/identity/automation/run');assert.equal(req.headers.authorization,'Bearer app-token');runs++;
  res.end(JSON.stringify(response({job:{id:id(2),grantId:id(1),tenantId:id(3),action:'directory.users.export',format:'csv',status,revision:'3',attemptCount:1}}).data));
 });
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const origin='http://127.0.0.1:'+server.address().port;
 try{
  const env={...process.env,OPENDIRECTORY_ISSUER:origin,OPENDIRECTORY_API_URL:origin,OPENDIRECTORY_CLIENT_ID:'worker',OPENDIRECTORY_CLIENT_SECRET:'disposable',OPENDIRECTORY_SCOPES:'company.automation',OPENDIRECTORY_ADMIN_ACCESS_TOKEN:''};
  const args=[fileURLToPath(new URL('../../od.mjs',import.meta.url)),'automation','worker',id(1),'--once'];
  const result=await promisify(execFile)(process.execPath,args,{env});const lines=result.stdout.trim().split('\n').map(line=>JSON.parse(line));
  assert.equal(lines[0].job.status,'succeeded');assert.deepEqual(lines[1],{workerStopped:true});assert.equal(runs,1);
  status='failed';await assert.rejects(promisify(execFile)(process.execPath,args,{env}),error=>error.code===2&&JSON.parse(error.stdout.split('\n')[0]).job.status==='failed');assert.equal(runs,2);
 }finally{await new Promise(resolve=>server.close(resolve));}
});
test('a complete four-MiB CSV artifact survives worst-case JSON transport escaping',async()=>{
 const content='\u0000'.repeat(4194304);const sha256=createHash('sha256').update(content).digest('hex');
 const server=http.createServer(async(req,res)=>{
  for await(const chunk of req){}res.setHeader('Content-Type','application/json');
  res.end(JSON.stringify(req.url==='/oauth/token'?{access_token:'app-token',token_type:'Bearer',expires_in:60}:response({jobId:id(1),content,sha256,contentType:'text/csv;charset=utf-8'}).data));
 });
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 try{const issuer='http://127.0.0.1:'+server.address().port;const client=createClient({issuer,clientId:'worker',clientSecret:'disposable'});assert.equal((await createAutomationClient(client).result(id(1))).content,content);}
 finally{await new Promise(resolve=>server.close(resolve));}
});

test('license scheduling pins one rule and rejects export formats or a substituted target', async () => {
 let calls = 0; let substitute = false;
 const client = createAutomationClient({ request: async (_method, _path, body) => { calls++; return response({ schedule: { ...body, tenantId: id(3), enabled: true, ruleId: substitute ? id(9) : body.ruleId } }, 201); } });
 await assert.rejects(client.enqueue(id(1), 'licenses.groups.reconcile', 'json')); await assert.rejects(client.enqueue(id(1), 'licenses.groups.reconcile', 'csv', id(4))); assert.equal(calls, 0);
 const plan = await client.schedule(id(1), 'licenses.groups.reconcile', 60, 'json', id(4)); assert.equal(plan.schedule.ruleId, id(4));
 substitute = true; await assert.rejects(client.schedule(id(1), 'licenses.groups.reconcile', 60, 'json', id(4)));
});

test('the actual license-sync CLI pins the rule and a partial worker report exits with code 2', async () => {
 let requested; let mismatch = false;
 const server = http.createServer(async (req, res) => {
  const chunks = []; for await (const chunk of req) chunks.push(chunk); res.setHeader('Content-Type', 'application/json');
  if (req.url === '/oauth/token') return res.end(JSON.stringify({ access_token: 'app-token', token_type: 'Bearer', expires_in: 60 }));
  requested = JSON.parse(Buffer.concat(chunks)); assert.equal(req.headers.authorization, 'Bearer app-token');
  if (req.url === '/api/identity/automation/schedules') { res.statusCode = 201; return res.end(JSON.stringify(response({ schedule: { ...requested, tenantId: id(3), enabled: true } }).data)); }
  assert.equal(req.url, '/api/identity/automation/run');
  res.end(JSON.stringify(response({ job: { id: id(2), grantId: id(1), tenantId: id(3), action: 'licenses.groups.reconcile', ruleId: id(4), format: 'json', status: mismatch ? 'succeeded' : 'partial', revision: '3', attemptCount: 1, retryCount: 0, rowCount: 2, artifactSha256: 'a'.repeat(64),
   progress: { runId: id(2), retryCount: 0, cycle: 1, completed: 2, total: 2, blocked: 1 } } }).data));
 });
 await new Promise(resolve => server.listen(0, '127.0.0.1', resolve)); const origin = 'http://127.0.0.1:' + server.address().port;
 try {
  const env = { ...process.env, OPENDIRECTORY_ISSUER: origin, OPENDIRECTORY_API_URL: origin, OPENDIRECTORY_CLIENT_ID: 'worker', OPENDIRECTORY_CLIENT_SECRET: 'disposable', OPENDIRECTORY_SCOPES: 'company.automation', OPENDIRECTORY_ADMIN_ACCESS_TOKEN: '' };
  const cli = (...args) => promisify(execFile)(process.execPath, [fileURLToPath(new URL('../../od.mjs', import.meta.url)), 'automation', ...args], { env });
  await cli('license-sync', id(1), id(4), '60'); assert.equal(requested.ruleId, id(4)); assert.equal(requested.intervalSeconds, 60); assert.equal(requested.format, 'json');
  await assert.rejects(cli('worker', id(1), '--once'), error => error.code === 2 && JSON.parse(error.stdout.split('\n')[0]).job.status === 'partial');
  mismatch = true; await assert.rejects(cli('worker', id(1), '--once'), error => error.code === 1 && !error.stdout.includes('succeeded'));
 } finally { await new Promise(resolve => server.close(resolve)); }
});
test('the script creates an explicit change subscription without inventing a timer or accepting export monitoring',async()=>{
 const calls=[];const client=createAutomationClient({request:async(...args)=>{calls.push(args);const body=args[2];return response({schedule:{...body,tenantId:id(4),intervalSeconds:null,lastSourceRevision:null,lastDeadlineRevision:null,enabled:true}},201);}});
 assert.equal((await client.watch(id(1),'directory.groups.reconcile',id(2))).schedule.onChange,true);assert.equal(calls[0][2].intervalSeconds,undefined);assert.equal(calls[0][2].onChange,true);assert.equal(calls[0][3].administrative,false);
 await assert.rejects(client.watch(id(1),'directory.users.export',id(2)));assert.equal(calls.length,1);
});
