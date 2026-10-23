'use strict';
const { test, beforeEach, afterEach, after } = require('node:test'); const assert = require('node:assert/strict'); const { randomUUID } = require('node:crypto');
const fs = require('node:fs'); const path = require('node:path'); const { Pool } = require('pg');
const { activeCompany } = require('../../../../../scripts/lib/company-owner-fixture.cjs');
const { CompanyAutomation } = require('../CompanyAutomation'); const { CompanyLicenseAuthority } = require('../CompanyLicenseAuthority'); const { AuthorizationState } = require('../AuthorizationState');
const administration = new Pool({ connectionString: process.env.IDENTITY_TEST_DATABASE_URL, max: 1 }); const issuer = 'https://automation.native'; const bearer = 'Bearer actual-owner'; const appBearer = 'Bearer actual-app';
let schema, pool, database, owner, automation, app, revoked, beforeCommit;
beforeEach(async()=>{
  schema='automation_'+randomUUID().replaceAll('-','');await administration.query('CREATE SCHEMA '+schema);
  pool=new Pool({connectionString:process.env.IDENTITY_TEST_DATABASE_URL,max:8,options:`-c search_path=${schema},public -c timezone=UTC`});
  database={isAvailable:()=>true,query:(...args)=>pool.query(...args),getClient:()=>pool.connect(),transaction:async(operation,options={})=>{const client=await pool.connect();try{
    await client.query(options.readOnly?'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY':'BEGIN');await client.query("SET LOCAL lock_timeout='3s';SET LOCAL statement_timeout='10s'");
    if(options.actor)await client.query("SELECT set_config('opendirectory.actor',$1,true)",[options.actor]);const result=await operation(client);if(beforeCommit&&!options.readOnly)await beforeCommit(client);await client.query('COMMIT');return result;
  }catch(error){await client.query('ROLLBACK');throw error;}finally{client.release();}}};
  const migrations=path.join(__dirname,'../../migrations');for(const file of fs.readdirSync(migrations).filter(file=>file.endsWith('.sql')).sort())await pool.query(fs.readFileSync(path.join(migrations,file),'utf8'));
  owner=await activeCompany(database,schema,issuer);revoked=false;beforeCommit=null;
  app={iss:issuer,sub:'automation-app',client_id:'automation-app',client_revision:'1',actor_type:'application',token_use:'access',jti:randomUUID(),exp:Math.floor(Date.now()/1000)+3600,scope:'company.automation',permissions:['company.automation']};
  const authority=new CompanyLicenseAuthority(database,{issuer,revalidate:async(_authorization,user)=>(await new AuthorizationState(database).state(issuer,user.sub)).tenant});
  automation=new CompanyAutomation(database,{issuer,authority,revalidate:async authorization=>{assert.equal(authorization,appBearer);if(revoked)throw Object.assign(new Error('Actual app revoked'),{status:401});}});
});
afterEach(async()=>{beforeCommit=null;await pool.end();await administration.query('DROP SCHEMA '+schema+' CASCADE');});after(async()=>administration.end());
async function grant(actions=['directory.users.export']){
 const enrollment=await automation.enroll({id:randomUUID(),name:'Actual tenant export worker'},app,appBearer);
 const input={id:randomUUID(),enrollmentId:enrollment.id,clientId:app.client_id,clientRevision:'1',actions,expiresAt:new Date(Date.now()+3600000).toISOString(),reason:'Explicit own-company app export delegation',confirm:true};
 const result=await automation.approve(input,owner.user,bearer);return{...result.grant,input};
}
const enqueue=permission=>automation.enqueue({id:randomUUID(),grantId:permission.id,action:permission.actions[0],format:'json'},app,appBearer);
test('a company-owned app enrollment is bound to its real original tenant and cannot be approved by a foreign actual owner',async()=>{
 const tenant=(await new AuthorizationState(database).state(issuer,owner.user.sub)).tenant;app.company_tenant=tenant;
 const enrollment=await automation.enroll({id:randomUUID(),name:'Tenant-owned automation application'},app,appBearer);assert.deepEqual(enrollment.companyTenant,tenant);
 const other=await activeCompany(database,schema,issuer);await assert.rejects(automation.enrollment(enrollment.id,other.user,bearer),{status:404});
 const input={id:randomUUID(),enrollmentId:enrollment.id,clientId:app.client_id,clientRevision:'1',actions:['directory.users.export'],expiresAt:new Date(Date.now()+3600000).toISOString(),reason:'Explicit app approval for the actual namespace',confirm:true};
 await assert.rejects(automation.approve(input,other.user,bearer),{status:404});
 await assert.rejects(automation.transaction(other.user,bearer,(client,actor)=>client.query(`INSERT INTO identity_automation_grants(id,enrollment_id,tenant_id,issuer,client_id,client_revision,actions,created_by,approval,reason,expires_at,status)
  VALUES($1,$2,$3,$4,$5,1,$6,$7,$8,$9,$10,'active')`,[input.id,input.enrollmentId,actor.source.tenant.id,issuer,app.client_id,input.actions,actor.source.actorUserId,actor.source,input.reason,input.expiresAt]),{ownerOnly:true}),{code:'42501'});
 assert.equal((await pool.query('SELECT count(*) AS n FROM identity_automation_grants')).rows[0].n,'0');
 const approved=await automation.approve(input,owner.user,bearer);await enqueue(approved.grant);owner.user.auth_time-=301;owner.user.mfa_authorization.authTime-=301;
 assert.equal((await automation.run({grantId:approved.grant.id},app,appBearer)).job.status,'succeeded');
 const substituted={...app,company_tenant:(await new AuthorizationState(database).state(issuer,other.user.sub)).tenant};await assert.rejects(automation.run({grantId:approved.grant.id},substituted,appBearer),{status:404});
});
test('actual roleless company app authority is a read-only original human source and requires fresh independent MFA',async()=>{
 const authority=new(require('../CompanyAppAuthority').CompanyAppAuthority)(database,{issuer,revalidate:async(_authorization,user)=>(await new AuthorizationState(database).state(issuer,user.sub)).tenant});
 const source=await authority.read(owner.user,bearer);assert.equal(Object.keys(source).length,11);assert.deepEqual(source.permissions,require('../../../../../packages/company-app-contract').PERMISSIONS);assert.equal(source.actorUserId,owner.receipt.administratorId);
 owner.user.auth_time-=301;owner.user.mfa_authorization.authTime-=301;await assert.rejects(authority.read(owner.user,bearer),{status:428});
});
test('parallel self-enrollment cannot exceed the actual pending enrollment limit',async()=>{
 const results=await Promise.allSettled(Array.from({length:11},()=>automation.enroll({id:randomUUID(),name:'Concurrent actual app enrollment'},app,appBearer)));
 assert.equal(results.filter(result=>result.status==='fulfilled').length,10);
 assert.equal(results.filter(result=>result.status==='rejected'&&result.reason.status===429).length,1);
 assert.equal(Number((await pool.query('SELECT count(*) AS n FROM identity_automation_enrollments')).rows[0].n),10);
});
test('actual roleless owner approves one exact app generation and the worker creates a real own-tenant artifact without a human session',async()=>{
 const permission=await grant();assert.deepEqual(owner.user.roles,[]);const other=await activeCompany(database,schema,issuer);
 const created=await enqueue(permission);owner.user.auth_time-=301;owner.user.mfa_authorization.authTime-=301;
 const result=await automation.run({grantId:permission.id},app,appBearer);assert.equal(result.job.id,created.job.id);assert.equal(result.job.status,'succeeded');assert.equal(result.job.attemptCount,1);
 const artifact=await automation.result(created.job.id,app,appBearer);const parsed=JSON.parse(artifact.content);assert.deepEqual(parsed.rows.map(row=>row.id),[owner.receipt.administratorId]);assert.equal(parsed.rows.some(row=>row.id===other.receipt.administratorId),false);
 assert.equal(artifact.content.includes('password'),false);assert.equal(artifact.content.includes('mfa'),false);
 assert.deepEqual((await automation.history(created.job.id,app,appBearer)).events.map(event=>event.status),['queued','running','succeeded']);
 assert.equal(await automation.run({grantId:permission.id},app,appBearer),null);
});
test('approval keys cannot substitute another client or tenant, and rotation/revocation denies use of the old delegation',async()=>{
 const permission=await grant();assert.deepEqual((await automation.approve(permission.input,owner.user,bearer)).grant.id,permission.id);
 await assert.rejects(automation.approve({...permission.input,clientId:'other-app'},owner.user,bearer),{status:409});
 const other=await activeCompany(database,schema,issuer);await assert.rejects(automation.enqueue({id:randomUUID(),grantId:permission.id,action:permission.actions[0],format:'csv'},other.user,bearer),{status:404});
 await assert.rejects(automation.run({grantId:permission.id},{...app,client_revision:'2'},appBearer),{status:404});
 revoked=true;await assert.rejects(automation.run({grantId:permission.id},app,appBearer),{status:401});
});
test('a live license job exposes only its own canonical group and recipient through an explicit machine proof without human MFA claims',async()=>{
 const {DirectoryCreator}=require('../DirectoryCreator');const {GroupMutator,groupEtag}=require('../GroupMutator');
 const revalidate=async(_auth,user)=>(await new AuthorizationState(database).state(issuer,user.sub)).tenant;
 const creator=new DirectoryCreator(database,{issuer,revalidate});let group=await creator.group({name:'Actual app license source'},owner.user,bearer);
 group=await new GroupMutator(database,{issuer,revalidate,revalidateAccess:async()=>{}}).add(group.id,{userId:owner.receipt.administratorId},groupEtag(group),owner.user,bearer);
 const other=await activeCompany(database,schema,issuer);const foreign=await creator.group({name:'Foreign private group'},other.user,bearer);
 const permission=await grant(['licenses.groups.reconcile']);const ruleId=randomUUID();
 const queued=await automation.enqueue({id:randomUUID(),grantId:permission.id,action:'licenses.groups.reconcile',format:'json',ruleId},app,appBearer);
 owner.user.auth_time-=301;owner.user.mfa_authorization.authTime-=301;
 let observed;
 automation.licenseClient={step:async job=>{
  const input={grantId:permission.id,jobId:job.id,leaseToken:job.lease_token,groupId:group.id,userId:owner.receipt.administratorId};
  observed=await automation.licenseSource(input,app,appBearer);
  assert.equal(require('../../../../../packages/company-license-automation-contract').validSource(observed,app,owner.receipt.administratorId),true);
  assert.deepEqual(observed.group.memberIds,[owner.receipt.administratorId]);assert.equal(observed.ruleId,ruleId);
  for(const field of ['context','actorUserId','identity_authorization','mfa_authorization','auth_time','roles'])assert.equal(Object.hasOwn(observed,field),false);
  await assert.rejects(automation.licenseSource({...input,groupId:foreign.id},app,appBearer),{status:404});
  await assert.rejects(automation.licenseSource({...input,userId:other.receipt.administratorId},app,appBearer),{status:404});
  await assert.rejects(automation.licenseSource({...input,leaseToken:randomUUID()},app,appBearer),{status:403});
  const base=await automation.licenseSource({...input,groupId:null,userId:null},app,appBearer);assert.equal(base.group,null);assert.equal(base.target,null);
  throw new Error('Stop before the separate policy receiver fixture');
 }};
 const result=await automation.run({grantId:permission.id},app,appBearer);assert.equal(result.job.status,'retry_wait');assert.equal(result.job.errorCode,'license_step_unconfirmed');assert.ok(observed);
 await assert.rejects(automation.licenseSource({grantId:permission.id,jobId:queued.job.id,leaseToken:observed.leaseToken,groupId:group.id,userId:null},app,appBearer),{status:403});
});
test('revocation atomically cancels queued work and schedules, prevents result access by the app, and retains all original evidence',async()=>{
 const permission=await grant();const queued=await enqueue(permission);const schedule=await automation.enqueue({id:randomUUID(),grantId:permission.id,action:permission.actions[0],format:'csv',intervalSeconds:60},app,appBearer,true);
 const revoked=await automation.revoke(permission.id,{confirm:true},`"company-automation-grant-${permission.id}-1"`,owner.user,bearer);assert.equal(revoked.grant.status,'revoked');
 assert.equal((await automation.list({grantId:permission.id},owner.user,bearer)).jobs[0].status,'cancelled');assert.equal((await automation.list({grantId:permission.id},owner.user,bearer,true)).schedules[0].enabled,false);
 await assert.rejects(automation.run({grantId:permission.id},app,appBearer),{status:403});await assert.rejects(automation.result(queued.job.id,app,appBearer),{status:403});
 await assert.rejects(pool.query('DELETE FROM identity_automation_events'),{code:'42501'});await assert.rejects(pool.query('TRUNCATE identity_automation_jobs CASCADE'),{code:'42501'});
 assert.ok(schedule.schedule.id);
});
test('license job checkpoints survive a new worker, retain partial results and begin an explicit new retry epoch', async () => {
 const permission = await grant(['licenses.groups.reconcile']); const ruleId = randomUUID();
 const queued = await automation.enqueue({ id: randomUUID(), grantId: permission.id, action: permission.actions[0], format: 'json', ruleId }, app, appBearer);
 const recipients = Array.from({ length: 27 }, () => randomUUID()); let finish = false; let blocked = 2;
 const licenseClient = { step: async row => ({ schemaVersion: 1, companyLicenseAutomationProtocol: 1, grantId: permission.id, jobId: row.id, ruleId,
  actor: { kind: 'application', id: permission.id, clientId: app.client_id, clientRevision: '1' },
  progress: { runId: row.id, retryCount: row.retry_count, cycle: 1, completed: finish ? 27 : 25, total: 27, blocked: finish ? blocked : 0 },
  finished: finish, hasBlocked: finish && blocked > 0, results: finish ? recipients.map((userId, index) => ({ userId, status: index < blocked ? 'blocked' : 'assigned', code: index < blocked ? 409 : null })) : [] }) };
 automation.licenseClient = licenseClient;
 const first = await automation.run({ grantId: permission.id }, app, appBearer);
 assert.equal(first.job.status, 'queued'); assert.equal(first.job.progress.completed, 25); assert.equal(first.job.attemptCount, 0); assert.equal(first.job.artifactSha256, null);
 finish = true;
 const restarted = new CompanyAutomation(database, { issuer, authority: automation.authority, revalidate: automation.revalidate, licenseClient });
 const second = await restarted.run({ grantId: permission.id }, { ...app, jti: randomUUID() }, appBearer);
 assert.equal(second.job.id, queued.job.id); assert.equal(second.job.status, 'partial'); assert.equal(second.job.rowCount, 27); assert.equal(second.job.progress.blocked, 2);
 const retained = await restarted.result(second.job.id, app, appBearer); assert.equal(JSON.parse(retained.content).hasBlocked, true);
 const retry = await restarted.changeJob(second.job.id, 'retry', `"company-automation-job-${second.job.id}-${second.job.revision}"`, owner.user, bearer);
 assert.equal(retry.job.status, 'queued'); assert.equal(retry.job.retryCount, 1); assert.equal(retry.job.progress.retryCount, 0); assert.equal(retry.job.artifactSha256, null);
 blocked = 0; const third = await restarted.run({ grantId: permission.id }, app, appBearer);
 assert.equal(third.job.status, 'succeeded'); assert.equal(third.job.progress.retryCount, 1);
 assert.deepEqual((await restarted.history(third.job.id, app, appBearer)).events.map(item => item.status), ['queued', 'running', 'queued', 'running', 'partial', 'queued', 'running', 'succeeded']);
});
test('a real elapsed schedule interval continues an unfinished license job instead of stacking another job', { timeout: 90000 }, async () => {
 const permission = await grant(['licenses.groups.reconcile']); const ruleId = randomUUID();
 const plan = await automation.enqueue({ id: randomUUID(), grantId: permission.id, action: permission.actions[0], ruleId, format: 'json', intervalSeconds: 60 }, app, appBearer, true);
 automation.licenseClient = { step: async row => ({ progress: { runId: row.id, retryCount: row.retry_count, cycle: 1, completed: 25, total: 27, blocked: 0 }, finished: false, hasBlocked: false, results: [] }) };
 const first = await automation.run({ grantId: permission.id }, app, appBearer); assert.equal(first.job.status, 'queued');
 const due = (await automation.list({ grantId: permission.id }, app, appBearer, true)).schedules[0].nextRunAt;
 await new Promise(resolve => setTimeout(resolve, Math.max(1, Date.parse(due) - Date.now() + 100)));
 const second = await automation.run({ grantId: permission.id }, { ...app, jti: randomUUID() }, appBearer);
 assert.equal(second.job.id, first.job.id); assert.equal(second.job.status, 'queued');
 assert.equal((await pool.query('SELECT count(*)::integer AS count FROM identity_automation_jobs WHERE schedule_id=$1', [plan.schedule.id])).rows[0].count, 1);
 assert.ok(Date.parse((await automation.list({ grantId: permission.id }, app, appBearer, true)).schedules[0].nextRunAt) > Date.parse(due));
});
test('concurrent workers claim one job only and scheduled runs survive a new worker instance without duplicate jobs',async()=>{
 const permission=await grant();await automation.enqueue({id:randomUUID(),grantId:permission.id,action:permission.actions[0],format:'csv',intervalSeconds:60},app,appBearer,true);
 const results=await Promise.all([automation.run({grantId:permission.id},app,appBearer),automation.run({grantId:permission.id},app,appBearer)]);assert.equal(results.filter(Boolean).length,1);
 assert.equal(Number((await pool.query('SELECT count(*) AS n FROM identity_automation_jobs')).rows[0].n),1);
 const restarted=new CompanyAutomation(database,{issuer,authority:automation.authority,revalidate:automation.revalidate});
 const repeated=await restarted.run({grantId:permission.id},app,appBearer);assert.equal(repeated,null);
 const artifact=await automation.result(results.find(Boolean).job.id,app,appBearer);assert.equal(artifact.contentType,'text/csv;charset=utf-8');assert.ok(artifact.content.startsWith('"id","username"'));
});
test('a transient export error produces a durable retry and explicit cancellation uses the actual job version',async()=>{
 const permission=await grant();const job=await enqueue(permission);automation.export=async()=>{throw new Error('Database connection lost with secret content');};
 const result=await automation.run({grantId:permission.id},app,appBearer);assert.equal(result.job.status,'retry_wait');assert.equal(result.job.errorCode,'export_unavailable');assert.ok(Date.parse(result.job.availableAt)>Date.now());
 await assert.rejects(automation.changeJob(job.job.id,'cancel',`"company-automation-job-${job.job.id}-1"`,owner.user,bearer),{status:412});
 const cancelled=await automation.changeJob(job.job.id,'cancel',`"company-automation-job-${job.job.id}-${result.job.revision}"`,owner.user,bearer);assert.equal(cancelled.job.status,'cancelled');
 assert.equal(JSON.stringify(await automation.history(job.job.id,owner.user,bearer)).includes('secret content'),false);
});
test('missing receiving guards and expired original approval reject rather than falling back to legacy permissions',async()=>{
 const enrollment=await automation.enroll({id:randomUUID(),name:'Deadline worker'},app,appBearer);
 const claims={...owner.user,exp:Math.floor(Date.now()/1000)+1};beforeCommit=async()=>{await new Promise(resolve=>setTimeout(resolve,Math.max(1,claims.exp*1000-Date.now()+80)));};
 await assert.rejects(automation.approve({id:randomUUID(),enrollmentId:enrollment.id,clientId:app.client_id,clientRevision:'1',actions:['directory.users.export'],expiresAt:new Date(Date.now()+3600000).toISOString(),reason:'Original approval deadline regression',confirm:true},claims,bearer));beforeCommit=null;
 assert.equal(Number((await pool.query('SELECT count(*) AS n FROM identity_automation_grants')).rows[0].n),0);
 await pool.query('ALTER TABLE identity_automation_jobs DISABLE TRIGGER identity_automation_commit');await assert.rejects(automation.grants(owner.user,bearer),{code:'42501'});
});
test('an abandoned expired worker lease is recovered by a fresh app token and never by a stale completion',async()=>{
 const permission=await grant();const created=await enqueue(permission);const actualExport=automation.export.bind(automation);const expiring={...app,exp:Math.floor(Date.now()/1000)+1};
 automation.export=async(...args)=>{await new Promise(resolve=>setTimeout(resolve,Math.max(1,expiring.exp*1000-Date.now()+70)));return actualExport(...args);};
 await assert.rejects(automation.run({grantId:permission.id},expiring,appBearer));automation.export=actualExport;
 const pending=(await automation.list({grantId:permission.id},app,appBearer)).jobs[0];assert.equal(pending.status,'running');
 const recovered=await automation.run({grantId:permission.id},{...app,jti:randomUUID()},appBearer);assert.equal(recovered.job.id,created.job.id);assert.equal(recovered.job.status,'succeeded');assert.equal(recovered.job.attemptCount,2);
});
test('an automation scope cannot piggyback canonical identity changes even after its scope setting is cleared',async()=>{
 const permission=await grant();
 await assert.rejects(automation.transaction(app,appBearer,async client=>{
  await automation.grant(client,permission.id,{kind:'application',issuer,clientId:app.client_id,clientRevision:'1'});
  await client.query("UPDATE users SET enabled=false WHERE id=$1",[owner.receipt.administratorId]);
 }),{code:'42501'});
 await assert.rejects(automation.transaction(app,appBearer,async(client,actor)=>{
  await automation.grant(client,permission.id,actor);
  await client.query("INSERT INTO identity_automation_jobs(id,grant_id,tenant_id,action,format,status) VALUES($1,$2,$3,'directory.users.export','json','queued')",[randomUUID(),permission.id,permission.tenantId]);
  await client.query("SELECT set_config('opendirectory.company_automation','',true)");await client.query('UPDATE users SET enabled=false WHERE id=$1',[owner.receipt.administratorId]);
 }),{code:'42501'});
 assert.equal((await pool.query('SELECT enabled FROM users WHERE id=$1',[owner.receipt.administratorId])).rows[0].enabled,true);
});
test('every offered dataset executes against real own canonical rows and migration replay preserves its artifacts',async()=>{
 const {DirectoryCreator}=require('../DirectoryCreator');const creator=new DirectoryCreator(database,{issuer,revalidate:async(_auth,user)=>(await new AuthorizationState(database).state(issuer,user.sub)).tenant});
 const team=await creator.group({name:'Actual own team'},owner.user,bearer);const unit=await creator.ou({name:'Actual own OU'},owner.user,bearer);
 const permission=await grant(['directory.groups.export','directory.ous.export']);
 for(const [action,expected] of [['directory.groups.export',team.id],['directory.ous.export',unit.id]]){
  const queued=await automation.enqueue({id:randomUUID(),grantId:permission.id,action,format:'json'},app,appBearer);
  const result=await automation.run({grantId:permission.id},app,appBearer);assert.equal(result.job.status,'succeeded');
  const artifact=await automation.result(queued.job.id,app,appBearer);assert.deepEqual(JSON.parse(artifact.content).rows.map(row=>row.id),[expected]);
  for(const file of ['048_company_automation.sql','049_company_license_automation.sql','051_company_group_rule_automation.sql','052_live_company_group_rules.sql','053_company_automation_changes.sql','054_company_app_automation_tenants.sql','055_employee_enrollments.sql'])await pool.query(fs.readFileSync(path.join(__dirname,'../../migrations',file),'utf8'));
  assert.equal((await automation.result(queued.job.id,app,appBearer)).sha256,artifact.sha256);
 }
});
test('read failures stop after five attempts and manual retry preserves the original failed history',async()=>{
 const permission=await grant();const queued=await enqueue(permission);const actualExport=automation.export.bind(automation);automation.export=async()=>{throw new Error('Transient test failure');};
 const original=database.transaction;
 // Fast-forward only retry availability; the separate retry test checks the real future backoff.
 database.transaction=(operation,options)=>original(client=>operation({query:(sql,values)=>client.query(sql,typeof sql==='string'&&sql.includes('available_at=clock_timestamp()+$4')?[...values.slice(0,3),0]:values)}),options);
 for(let attempt=1;attempt<=5;attempt++){
  const result=await automation.run({grantId:permission.id},app,appBearer);assert.equal(result.job.attemptCount,attempt);assert.equal(result.job.status,attempt===5?'failed':'retry_wait');
 }
 assert.equal(await automation.run({grantId:permission.id},app,appBearer),null);
 const failed=(await automation.list({grantId:permission.id},app,appBearer)).jobs[0];
 const restarted=await automation.changeJob(queued.job.id,'retry',`"company-automation-job-${failed.id}-${failed.revision}"`,owner.user,bearer);assert.equal(restarted.job.retryCount,1);assert.equal(restarted.job.attemptCount,0);
 automation.export=actualExport;assert.equal((await automation.run({grantId:permission.id},app,appBearer)).job.status,'succeeded');
 const history=await automation.history(queued.job.id,app,appBearer);assert.equal(history.events.filter(event=>event.status==='failed').length,1);assert.equal(history.events.at(-1).status,'succeeded');
});
test('an incoherent restored OU cannot leak a foreign parent through an export artifact',async()=>{
 const {DirectoryCreator}=require('../DirectoryCreator');const creator=new DirectoryCreator(database,{issuer,revalidate:async(_auth,user)=>(await new AuthorizationState(database).state(issuer,user.sub)).tenant});
 const own=await creator.ou({name:'Own OU'},owner.user,bearer);const other=await activeCompany(database,schema,issuer);const foreign=await creator.ou({name:'Foreign OU'},other.user,bearer);
 await pool.query('ALTER TABLE ous DISABLE TRIGGER USER');
 try{await pool.query('UPDATE ous SET parent_id=$2 WHERE id=$1',[own.id,foreign.id]);}finally{await pool.query('ALTER TABLE ous ENABLE TRIGGER USER');}
 const permission=await grant(['directory.ous.export']);const queued=await enqueue(permission);const result=await automation.run({grantId:permission.id},app,appBearer);
 assert.equal(result.job.status,'retry_wait');assert.equal(result.job.errorCode,'export_unavailable');await assert.rejects(automation.result(queued.job.id,app,appBearer),{status:409});
 assert.equal((await pool.query('SELECT artifact_content FROM identity_automation_jobs WHERE id=$1',[queued.job.id])).rows[0].artifact_content,null);
});
test('artifact read and subsequent worker admission reject a restored but corrupted original job record',async()=>{
 const permission=await grant();const queued=await enqueue(permission);
 await pool.query('ALTER TABLE identity_automation_jobs DISABLE TRIGGER identity_automation_before;ALTER TABLE identity_automation_jobs DISABLE TRIGGER identity_automation_event;ALTER TABLE identity_automation_jobs DISABLE TRIGGER identity_automation_commit');
 try{await pool.query("UPDATE identity_automation_jobs SET format='csv' WHERE id=$1",[queued.job.id]);}finally{await pool.query('ALTER TABLE identity_automation_jobs ENABLE TRIGGER identity_automation_before;ALTER TABLE identity_automation_jobs ENABLE TRIGGER identity_automation_event;ALTER TABLE identity_automation_jobs ENABLE TRIGGER identity_automation_commit');}
 await assert.rejects(automation.list({grantId:permission.id},app,appBearer),{status:503});await assert.rejects(automation.run({grantId:permission.id},app,appBearer),{status:503});
});
test('an abandoned fifth lease becomes a visible failed result instead of an unclaimable running job',async()=>{
 const permission=await grant();await enqueue(permission);const original=database.transaction;const actualExport=automation.export.bind(automation);
 database.transaction=(operation,options)=>original(client=>operation({query:(sql,values)=>client.query(sql,typeof sql==='string'&&sql.includes('available_at=clock_timestamp()+$4')?[...values.slice(0,3),0]:values)}),options);
 automation.export=async()=>{throw new Error('Transient read');};for(let index=0;index<4;index++)assert.equal((await automation.run({grantId:permission.id},app,appBearer)).job.status,'retry_wait');
 const expiring={...app,exp:Math.floor(Date.now()/1000)+1};automation.export=async(...args)=>{await new Promise(resolve=>setTimeout(resolve,Math.max(1,expiring.exp*1000-Date.now()+70)));return actualExport(...args);};
 await assert.rejects(automation.run({grantId:permission.id},expiring,appBearer));automation.export=actualExport;
 const result=await automation.run({grantId:permission.id},app,appBearer);assert.equal(result.job.status,'failed');assert.equal(result.job.attemptCount,5);assert.equal(result.job.errorCode,'lease_expired');
});
test('a standing license change subscription observes its exact app grant and queues capacity changes without any directory change',async()=>{
 const {DirectoryCreator}=require('../DirectoryCreator');const revalidate=async(_auth,user)=>(await new AuthorizationState(database).state(issuer,user.sub)).tenant;
 const collection=await new DirectoryCreator(database,{issuer,revalidate}).group({name:'Actual capacity watch group'},owner.user,bearer);
 const permission=await grant(['licenses.groups.reconcile']);const ruleId=randomUUID();const poolId=randomUUID();const plan=(await automation.enqueue({id:randomUUID(),grantId:permission.id,action:'licenses.groups.reconcile',format:'json',ruleId,onChange:true},app,appBearer,true)).schedule;
 const metadata={revision:'1',available:0};const contract=require('../../../../../packages/company-automation-change-contract');
 automation.licenseClient={observe:async row=>{
  const context={grantId:row.grant_id,scheduleId:row.id,ruleId:row.rule_id};const source=await automation.watchSource(context,app,appBearer);assert.equal(contract.watch(source,context,app),source);
  return{schemaVersion:1,companyAutomationChangeProtocol:1,allocationMode:'local-only',...context,scheduleRevision:source.scheduleRevision,tenantId:source.tenant.id,groupId:collection.id,poolId,ruleRevision:'1',ruleStatus:'active',poolRevision:metadata.revision,availableSeats:metadata.available,validUntil:source.validUntil,tokenIdentifierHash:source.tokenIdentifierHash};
 },step:async row=>({progress:{runId:row.id,retryCount:row.retry_count,cycle:1,completed:0,total:0,blocked:0},finished:true,hasBlocked:false,results:[]})};
 owner.user.auth_time-=301;owner.user.mfa_authorization.authTime-=301;
 const first=await automation.run({grantId:permission.id},app,appBearer);assert.equal(first.job.status,'succeeded');assert.equal(first.job.trigger.availableSeats,0);assert.equal(await automation.run({grantId:permission.id},app,appBearer),null);
 const physical=(await pool.query('SELECT revision FROM groups WHERE id=$1',[collection.id])).rows[0].revision;
 metadata.revision='2';metadata.available=1;const second=await automation.run({grantId:permission.id},app,appBearer);assert.equal(second.job.status,'succeeded');assert.equal(second.job.trigger.poolRevision,'2');assert.equal(second.job.trigger.availableSeats,1);assert.notEqual(second.job.id,first.job.id);
 assert.equal((await pool.query('SELECT revision FROM groups WHERE id=$1',[collection.id])).rows[0].revision,physical);assert.equal(second.job.trigger.sourceRevision,first.job.trigger.sourceRevision);assert.equal(await automation.run({grantId:permission.id},app,appBearer),null);
 await assert.rejects(automation.watchSource({grantId:permission.id,scheduleId:plan.id,ruleId:randomUUID()},app,appBearer),{status:404});
 await assert.rejects(automation.watchSource({grantId:permission.id,scheduleId:plan.id,ruleId},owner.user,bearer),{status:403});
});
test('an unavailable change observation does not acknowledge its checkpoint or prevent a separately queued authorized export',async()=>{
 const permission=await grant(['licenses.groups.reconcile','directory.users.export']);const ruleId=randomUUID();const plan=(await automation.enqueue({id:randomUUID(),grantId:permission.id,action:'licenses.groups.reconcile',format:'json',ruleId,onChange:true},app,appBearer,true)).schedule;
 automation.licenseClient={observe:async()=>{throw Object.assign(new Error('Actual source temporarily unavailable'),{status:503});}};
 const queued=await automation.enqueue({id:randomUUID(),grantId:permission.id,action:'directory.users.export',format:'json'},app,appBearer);
 const first=await automation.run({grantId:permission.id},app,appBearer);assert.equal(first.job.id,queued.job.id);assert.equal(first.job.status,'succeeded');
 await assert.rejects(automation.run({grantId:permission.id},app,appBearer),{status:503});assert.equal((await pool.query('SELECT source_checkpoint FROM identity_automation_schedules WHERE id=$1',[plan.id])).rows[0].source_checkpoint,null);
});
