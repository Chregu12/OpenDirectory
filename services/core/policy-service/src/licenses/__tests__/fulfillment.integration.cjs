'use strict';

const { test,before,beforeEach,after,afterEach }=require('node:test');
const assert=require('node:assert/strict');
const { randomUUID }=require('node:crypto');
const fs=require('node:fs'); const path=require('node:path'); const http=require('node:http');
const os=require('node:os'); const { spawn }=require('node:child_process');
const { Pool }=require('pg');
const { LicenseAllocator }=require('../LicenseAllocator');
const { GroupLicenseAllocator }=require('../GroupLicenseAllocator');
const { groupSnapshot }=require('../../../../../../scripts/lib/group-license-snapshot-fixture.cjs');
const { LicenseGrants,etag:grantEtag }=require('../LicenseGrants');
const { LicenseReviews }=require('../LicenseReviews');
const { ProviderStore }=require('../fulfillment/ProviderStore');
const { GraphLicenseClient }=require('../fulfillment/GraphLicenseClient');
const { FulfillmentWorker }=require('../fulfillment/FulfillmentWorker');
const { etag }=require('../fulfillment/contracts');
const { assertWorkerDatabase }=require('../fulfillment/databasePrivileges');
const {capacityAdmissionFixture}=require('../../../../../../scripts/lib/license-capacity-admission-fixture.cjs');
const schema='fulfillment_'+randomUUID().replaceAll('-',''); const admin=new Pool({ connectionString:process.env.LICENSE_TEST_DATABASE_URL,max:1 });
let database; let pool; let server; let origin; let remote; let calls; let writeBehavior; let readBehavior;const capacityFixtures=[];
before(async()=>{
  await admin.query('CREATE SCHEMA '+schema); pool=new Pool({ connectionString:process.env.LICENSE_TEST_DATABASE_URL,max:10,options:`-c search_path=${schema},public` });
  database={ query:(...args)=>pool.query(...args),getClient:()=>pool.connect() };
  for (const name of fs.readdirSync(path.join(__dirname,'../../db/migrations')).filter(name=>/^(00[4-9]|01[0-7]|02[0-2])_.*\.sql$/.test(name)).sort()) await pool.query(fs.readFileSync(path.join(__dirname,'../../db/migrations',name),'utf8'));
  server=http.createServer(async(req,res)=>{
    const chunks=[]; for await (const chunk of req) chunks.push(chunk); const body=Buffer.concat(chunks).toString(); calls.push({ method:req.method,url:req.url,body,authorization:req.headers.authorization });
    res.setHeader('Content-Type','application/json');
    if (req.url.endsWith('/oauth2/v2.0/token')) return res.end(JSON.stringify({ access_token:'isolated-graph-token',token_type:'Bearer',expires_in:3600 }));
    assert.equal(req.headers.authorization,'Bearer isolated-graph-token');
    if (req.method==='GET') {
      if (readBehavior) await readBehavior(req,res);
      if (res.writableEnded) return;
      return res.end(JSON.stringify(remote));
    }
    if (writeBehavior) { await writeBehavior(req,res,JSON.parse(body)); if (res.writableEnded || res.destroyed) return; }
    const input=JSON.parse(body); assert.equal(input.addLicenses.length+input.removeLicenses.length,1);
    if (input.addLicenses.length) {
      const entry=input.addLicenses[0]; remote.assignedLicenses=[entry]; remote.licenseAssignmentStates=[{ ...entry,assignedByGroup:null,state:'Active',error:null }];
    } else { remote.assignedLicenses=[]; remote.licenseAssignmentStates=[]; }
    res.end(JSON.stringify({ id:remote.id }));
  }); await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve)); origin='http://127.0.0.1:'+server.address().port;
});
beforeEach(async()=>{
  await pool.query('CREATE OR REPLACE FUNCTION license_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp(); $$');
  await pool.query('CREATE OR REPLACE FUNCTION license_capacity_now() RETURNS timestamptz LANGUAGE sql VOLATILE SECURITY INVOKER AS $$ SELECT clock_timestamp(); $$');
  await pool.query('TRUNCATE license_provider_connectors,license_catalog,license_subjects,license_requests,license_audit_events,license_assignment_sources,license_group_rules CASCADE');
  remote={ id:randomUUID(),accountEnabled:true,assignedLicenses:[],licenseAssignmentStates:[] }; calls=[]; writeBehavior=null; readBehavior=null;
});
after(async()=>{ server.closeAllConnections(); await new Promise(resolve=>server.close(resolve)); await pool.end(); await admin.query('DROP SCHEMA '+schema+' CASCADE'); await admin.end(); });
afterEach(async()=>{for(const capacity of capacityFixtures.splice(0))await capacity.close();});
function operator(roles=['license-provider-administrator']) {
  const userId=randomUUID(); const authTime=Math.floor(Date.now()/1000);
  const principal={ issuer:'https://fulfillment.test',subject:randomUUID(),userId,enabled:true };
  return { principal,user:{ iss:principal.issuer,sub:principal.subject,actor_type:'user',roles,identity_authorization:{ userId,revision:'1',linkRevision:'1',rolesRevision:'a'.repeat(64) },
    auth_time:authTime,amr:['pwd','otp'],mfa_authorization:{ schemaVersion:1,userId,revision:'1',authTime,methods:['pwd','otp'] } } };
}
async function fixture({ assign=true,enable=true,capacityReview=true,capacityUnits=100 }={}) {
  const targetUser=randomUUID(); let snapshot={ schemaVersion:1,userId:targetUser,revision:'1',enabled:true,deleted:false };
  const identity={ user:async userId=>({...structuredClone(snapshot),userId}) }; const source={ user:async userId=>({...structuredClone(snapshot),userId}),snapshot:async groupId=>groupSnapshot({groupId,name:'Owned provider group',revision:'1',memberIds:[targetUser]}) };
  const allocator=new LicenseAllocator(database,{ source });new GroupLicenseAllocator({allocator,source}); const store=new ProviderStore(allocator,{ revalidate:async()=>{} }); const actor=operator(); const reason='Reviewed exclusive direct Microsoft license management';
  const license=(await pool.query("INSERT INTO license_catalog(name,total_seats) VALUES('Owned provider fixture',5) RETURNING *")).rows[0];
  const connector=await store.create('connectors',{ tenantId:randomUUID(),reason },actor.user,actor.principal);
  const product=await store.create('products',{ connectorId:connector.id,licenseId:license.id,skuId:randomUUID(),disabledPlans:[],exclusiveDirectManagement:true,reason },actor.user,actor.principal);
  const subject=await store.create('subjects',{ connectorId:connector.id,userId:targetUser,objectId:remote.id,exclusiveDirectManagement:true,reason },actor.user,actor.principal,'Bearer owned-fixture');
  if (enable) for (const [kind,row] of [['connectors',connector],['products',product],['subjects',subject]]) await store.enable(kind,row.id,etag(kind,row.id,row.version),{ enabled:true,reason },actor.user,actor.principal);
  if (assign) await allocator.assign(license.id,{ assignee_type:'user',assignee_id:targetUser },actor.principal.userId);
  const graph=()=>new GraphLicenseClient({ tenantId:connector.tenantId,clientId:randomUUID(),clientSecret:'isolated-provider-secret',fetchImpl:(url,options)=>fetch(origin+new URL(url).pathname+new URL(url).search,options) });
  const worker=()=>new FulfillmentWorker({ store,identity,graph:graph(),connectorId:connector.id,tenantId:connector.tenantId,sourceClientId:'owned-workload-client' });
  const target=()=>store.lookup(license.id,targetUser,actor.user);
  let capacity;
  if(enable){capacity=await capacityAdmissionFixture({database,admin,connectionString:process.env.LICENSE_TEST_DATABASE_URL,schema,connector,product,review:capacityReview,units:capacityUnits});capacityFixtures.push(capacity);}
  return { allocator,store,actor,license,connector,product,subject,worker,target,identity,capacity,update:patch=>{ snapshot={ ...snapshot,...patch }; } };
}
const writes=()=>calls.filter(call=>call.method==='POST' && call.url.endsWith('/assignLicense'));

test('legacy provider readers and workers exclude an injected company-owned pool without checkpoint, error or Graph effects',async()=>{
 const context=await fixture();const view=await context.target();const row=await context.store.row(view.id);
 const client=await pool.connect();
 try{await client.query('BEGIN');await client.query('ALTER TABLE license_catalog DISABLE TRIGGER USER');await client.query('UPDATE license_catalog SET business_tenant_id=$2,business_revision=1 WHERE id=$1',[context.license.id,randomUUID()]);await client.query('ALTER TABLE license_catalog ENABLE TRIGGER USER');await client.query('COMMIT');}
 catch(error){await client.query('ROLLBACK');throw error;}finally{client.release();}
 try{
 const retained=(await pool.query('SELECT to_jsonb(target) AS state FROM license_fulfillment_targets target WHERE id=$1',[row.id])).rows[0];
 const events=(await pool.query('SELECT count(*)::text AS count FROM license_fulfillment_events')).rows[0].count;
 assert.equal(await context.store.row(row.id),undefined);assert.deepEqual(await context.store.candidates(context.connector.id),[]);
 for(const operation of [
  ()=>context.target(),()=>context.store.get('products',context.product.id),
  ()=>context.store.enable('products',context.product.id,etag('products',context.product.id,context.product.version),{enabled:false,reason:'Controlled legacy namespace exclusion check'},context.actor.user,context.actor.principal),
  ()=>context.store.refresh(row),
  ()=>context.store.checkpoint(row,{schemaVersion:1,userId:row.user_id,revision:'2',enabled:false,deleted:true},{}),
  ()=>context.store.writeIntent(row,{}),()=>context.store.dispatch(row,randomUUID()),
  ()=>context.store.resolve(row.id,'adopt',etag('targets',row.id,row.version),{reason:'Controlled legacy namespace exclusion check',acknowledgeExclusiveManagement:true},context.actor.user,context.actor.principal,'Bearer owned-fixture'),
 ])await assert.rejects(operation,error=>error.status===404);
 await context.store.settle(row,{}, {status:'failed',error:'must_not_be_written'});
 let sources=0;context.identity.user=async()=>{sources++;throw new Error('Company target reached a legacy identity source');};
 await context.worker().target(row.id);assert.equal(sources,0);assert.equal(calls.length,0);
 const report=await new(require('../fulfillment/CapacityReports').CapacityReports)(context.allocator,{revalidate:async()=>{}}).get(context.connector.id,context.actor.user,context.actor.principal,'Bearer owned-fixture');assert.deepEqual(report.products,[]);
 assert.deepEqual((await pool.query('SELECT to_jsonb(target) AS state FROM license_fulfillment_targets target WHERE id=$1',[row.id])).rows[0],retained);
 assert.equal((await pool.query('SELECT count(*)::text AS count FROM license_fulfillment_events')).rows[0].count,events);
 }finally{
  const cleanup=await pool.connect();try{await cleanup.query('BEGIN');await cleanup.query('ALTER TABLE license_catalog DISABLE TRIGGER USER');await cleanup.query('UPDATE license_catalog SET business_tenant_id=NULL,business_revision=NULL WHERE id=$1',[context.license.id]);await cleanup.query('ALTER TABLE license_catalog ENABLE TRIGGER USER');await cleanup.query('COMMIT');}catch(error){await cleanup.query('ROLLBACK');throw error;}finally{cleanup.release();}
 }
});

test('an unanswered source review reaches provider withdrawal through the actual capped entitlement and separate observation',async()=>{
  const context=await fixture(); const actor=operator(['license-review-administrator']); const voter=operator(['license-reviewer']);
  const reviews=new LicenseReviews(context.allocator,{ source:{ reviewer:async()=>({ canReview:true }) },revalidate:async()=>{} });
  await reviews.create({ licenseId:context.license.id,intervalSeconds:3600,windowSeconds:60,reviewerUserIds:[voter.principal.userId],reason:'Actual reviewed vendor entitlement cutoff',acknowledgeDeadlines:true },actor.user,actor.principal,'Bearer owned-fixture');
  const target=await context.target(); await context.worker().target(target.id); await context.worker().target(target.id); assert.equal(writes().length,1);
  await pool.query("CREATE OR REPLACE FUNCTION license_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+interval '61 seconds'; $$");
  await context.worker().target(target.id); assert.equal(writes().length,2); assert.equal((await context.target()).desired,false); assert.equal((await context.target()).status,'verifying');
  await context.worker().target(target.id); assert.deepEqual(remote.assignedLicenses,[]); assert.equal((await context.target()).status,'confirmed');
});

test('conditional source withdrawal queues provider removal atomically and requires a later owned observation',async()=>{
  const context=await fixture(); const target=await context.target(); await context.worker().target(target.id); await context.worker().target(target.id);
  const grants=new LicenseGrants(context.allocator,{ revalidate:async()=>{} }); const actor=operator(['license-manager']);
  const grantId=(await pool.query('SELECT grant_id FROM license_assignment_sources WHERE license_id=$1',[context.license.id])).rows[0].grant_id;
  const before=await grants.get(context.license.id,grantId);
  const receipt=await grants.revoke(context.license.id,grantId,grantEtag(before),{ confirm:true,reason:'Reviewed exact source withdrawal' },actor.user,actor.principal,'Bearer owned-fixture');
  assert.equal(receipt.localOnly,true); assert.equal(receipt.sourcesRemoved,1); assert.equal(receipt.grant.state,'revoked');
  assert.equal((await context.target()).desired,false); assert.equal(writes().length,1);
  await context.worker().target(target.id); assert.equal(writes().length,2); assert.equal((await context.target()).status,'verifying');
  await context.worker().target(target.id); assert.equal((await context.target()).status,'confirmed'); assert.deepEqual(remote.assignedLicenses,[]);
});

test('loss of original issuer authority after source DML rolls back grant evidence and provider desired state',async()=>{
  const context=await fixture(); const target=await context.target(); const actor=operator(['license-manager']); let validations=0;
  const grants=new LicenseGrants(context.allocator,{ revalidate:async()=>{ if (++validations===2) throw Object.assign(new Error('Owned revoked session'),{ status:401 }); } });
  const grantId=(await pool.query('SELECT grant_id FROM license_assignment_sources WHERE license_id=$1',[context.license.id])).rows[0].grant_id;
  const before=await grants.get(context.license.id,grantId);
  await assert.rejects(grants.revoke(context.license.id,grantId,grantEtag(before),{ confirm:true,reason:'Reviewed source withdrawal with authority loss' },actor.user,actor.principal,'Bearer owned-fixture'),error=>error.status===401);
  assert.equal(validations,2); assert.deepEqual(await grants.get(context.license.id,grantId),before);
  assert.deepEqual(await context.target(),target); assert.equal((await pool.query('SELECT used_seats FROM license_catalog WHERE id=$1',[context.license.id])).rows[0].used_seats,1);
});
test('a real dedicated worker database identity can fulfill but cannot create local rights, retarget bindings or impersonate an administrative connection',async()=>{
  const context=await fixture(); const target=await context.target(); const role='fulfillment_worker_'+randomUUID().replaceAll('-',''); let limited;
  const password='owned-'+randomUUID(); await assert.rejects(assertWorkerDatabase(database)); await admin.query(`CREATE ROLE ${role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOINHERIT PASSWORD '${password}'`);
  try {
    const grants=fs.readFileSync(path.join(__dirname,'../../../scripts/license-fulfillment-grants.sql'),'utf8').replaceAll(':"license_schema"',`"${schema}"`).replaceAll(':"worker_role"',`"${role}"`); await pool.query(grants);
    const url=new URL(process.env.LICENSE_TEST_DATABASE_URL); url.username=role; url.password=password;
    limited=new Pool({ connectionString:url.toString(),max:4,options:`-c search_path=${schema},public` }); const restricted={ query:(...args)=>limited.query(...args),getClient:()=>limited.connect() };
    await assertWorkerDatabase(restricted); const worker=context.worker(); worker.store=new ProviderStore(new LicenseAllocator(restricted));
    assert.deepEqual((await limited.query('SELECT id,business_tenant_id FROM license_catalog WHERE id=$1',[context.license.id])).rows,[{id:context.license.id,business_tenant_id:null}]);
    for(const column of ['name','vendor','cost_per_seat','notes'])await assert.rejects(limited.query(`SELECT ${column} FROM license_catalog`),error=>error.code==='42501');
    await worker.target(target.id); await worker.target(target.id); assert.equal((await context.target()).status,'confirmed');
    await assert.rejects(limited.query('SELECT * FROM license_review_audit'),error=>error.code==='42501');
    await pool.query(`GRANT TRUNCATE ON license_review_leases TO ${role}`);
    await assert.rejects(assertWorkerDatabase(restricted),/may not change/);
    await pool.query(`REVOKE TRUNCATE ON license_review_leases FROM ${role}`); await assertWorkerDatabase(restricted);
    await assert.rejects(limited.query('SELECT * FROM license_scope_pim_audit'),error=>error.code==='42501');
    for(const table of ['license_group_observations','license_group_member_leases','license_group_lease_audit','license_scope_eligibilities','license_scope_activation_requests','license_scope_pim_audit','license_scope_activation_policies','license_scope_policy_audit','license_scope_review_policies','license_scope_review_leases','license_scope_review_fences','license_scope_review_audit']){
      await assert.rejects(limited.query('SELECT * FROM '+table),error=>error.code==='42501');
      await pool.query(`GRANT TRUNCATE ON ${table} TO ${role}`);await assert.rejects(assertWorkerDatabase(restricted),/may not change/);await pool.query(`REVOKE TRUNCATE ON ${table} FROM ${role}`);
    }
    await assertWorkerDatabase(restricted);
    for(const table of ['license_capacity_budgets','license_capacity_reservations','license_capacity_admission_events','license_capacity_admission_outbox']){
      await assert.rejects(limited.query('SELECT * FROM '+table),error=>error.code==='42501');
      await pool.query(`GRANT TRUNCATE ON ${table} TO ${role}`);await assert.rejects(assertWorkerDatabase(restricted),/must not publish/);await pool.query(`REVOKE TRUNCATE ON ${table} FROM ${role}`);
    }
    await assert.rejects(limited.query('UPDATE license_provider_subjects SET enabled=false,version=version+1 WHERE id=$1',[context.subject.id]),error=>error.code==='42501');
    await assert.rejects(limited.query("INSERT INTO license_assignments(license_id,assignee_type,assignee_id) VALUES($1,'user',$2)",[context.license.id,randomUUID()]),error=>error.code==='42501');
    await assert.rejects(limited.query('DELETE FROM license_assignments WHERE license_id=$1',[context.license.id]),error=>error.code==='42501');
    const current=await context.store.get('connectors',context.connector.id);
    await context.store.enable('connectors',current.id,etag('connectors',current.id,current.version),{ enabled:false,reason:'Reviewed isolated paused command startup fixture' },context.actor.user,context.actor.principal);
    const directory=fs.mkdtempSync(path.join(os.tmpdir(),'od-fulfillment-cli-')); const filename=path.join(directory,'worker.json'); let child;
    try {
      fs.writeFileSync(filename,JSON.stringify({ enabled:true,connectorId:context.connector.id,tenantId:context.connector.tenantId,graphClientId:randomUUID(),graphClientSecret:'private-inactive-fixture',sourceClientId:'owned-paused-worker',sourceClientSecret:'private-inactive-fixture',sourceTokenUrl:'http://127.0.0.1:1/oauth/token',identityUrl:'http://127.0.0.1:1/' }),{ mode:0o600 });
      url.searchParams.set('options',`-c search_path=${schema},public`); url.searchParams.set('application_name','owned-fulfillment-cli'); const before=calls.length; let output='';
      child=spawn(process.execPath,['scripts/license-fulfillment-worker.js'],{ cwd:path.join(__dirname,'../../..'),stdio:['ignore','pipe','pipe'],env:{ ...process.env,DATABASE_URL:url.toString(),PG_POOL_MAX:'3',LICENSE_FULFILLMENT_CONFIG_FILE:filename,LOG_LEVEL:'error' } });
      for(const stream of [child.stdout,child.stderr]) stream.on('data',chunk=>{ output=(output+chunk).slice(-2000); });
      let ready=false; const deadline=Date.now()+4000;
      while(Date.now()<deadline && child.exitCode===null && child.signalCode===null) {
        ready=(await pool.query("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename=$1 AND application_name='owned-fulfillment-cli' AND state='idle' AND query LIKE 'SELECT target.id FROM license_fulfillment_targets target JOIN%') AS ready",[role])).rows[0].ready;
        if(ready)break; await new Promise(resolve=>setTimeout(resolve,20));
      }
      assert.equal(ready,true,output);
      const exited=new Promise((resolve,reject)=>{ const timer=setTimeout(()=>reject(new Error('Owned worker did not stop')),5000); child.once('exit',code=>{ clearTimeout(timer);resolve(code); }); }); child.kill('SIGTERM'); assert.equal(await exited,0); assert.equal(calls.length,before);
    } finally { if(child && child.exitCode===null && child.signalCode===null) { const stopped=new Promise(resolve=>child.once('exit',resolve)); child.kill('SIGKILL'); await stopped; } fs.rmSync(directory,{ recursive:true,force:true }); }
  } finally { if (limited) await limited.end(); await pool.query(`DROP OWNED BY ${role}`); await admin.query(`DROP ROLE ${role}`); }
});
test('transactional desired state drives only the mapped Graph user and SKU; successful mutation alone is not provisioned',async()=>{
  const context=await fixture(); const target=await context.target(); assert.equal(target.desired,true);
  await context.worker().target(target.id); assert.equal((await context.target()).status,'verifying'); assert.equal(writes().length,1);
  assert.deepEqual(JSON.parse(writes()[0].body),{ addLicenses:[{ skuId:context.product.skuId,disabledPlans:[] }],removeLicenses:[] });
  assert.equal(writes()[0].url,`/v1.0/users/${context.subject.objectId}/assignLicense`);
  await context.worker().target(target.id); assert.equal((await context.target()).status,'confirmed'); assert.equal(writes().length,1);
  await context.allocator.revoke(context.license.id,context.subject.userId,context.actor.principal.userId,'user');
  await context.worker().target(target.id); assert.equal((await context.target()).status,'verifying'); await context.worker().target(target.id);
  assert.equal((await context.target()).desired,false); assert.equal((await context.target()).status,'confirmed'); assert.equal((await context.target()).owned,false);
  assert.deepEqual(JSON.parse(writes()[1].body),{ addLicenses:[],removeLicenses:[context.product.skuId] });
  const evidence=JSON.stringify((await pool.query('SELECT actor,details FROM license_fulfillment_events')).rows);
  assert.equal(evidence.includes('isolated-graph-token')||evidence.includes('isolated-provider-secret'),false);
});
test('overlapping local sources preserve one vendor assignment until the final effective entitlement disappears',async()=>{
  const context=await fixture(); const target=await context.target(); await context.worker().target(target.id); await context.worker().target(target.id);
  const groupId=randomUUID();
  await context.allocator.assign(context.license.id,{assignee_type:'group',assignee_id:groupId},context.actor.principal.userId,{});
  await context.allocator.revoke(context.license.id,context.subject.userId,context.actor.principal.userId,'user'); await context.worker().target(target.id);
  assert.equal((await context.target()).desired,true); assert.equal(writes().length,1);
  await context.allocator.transaction(async client=>{
    await client.query('DELETE FROM license_assignment_sources WHERE license_id=$1 AND user_id=$2',[context.license.id,context.subject.userId]);
    await context.allocator.syncUser(client,context.license.id,context.subject.userId,context.actor.principal.userId);
  });
  await context.worker().target(target.id); assert.equal(writes().length,2); assert.equal((await context.target()).desired,false);
});
test('a directory outage cannot keep the actual provider desired state positive beyond the physical group lease without any local sweep',async()=>{
 const context=await fixture({assign:false});const groupId=randomUUID();await context.allocator.assign(context.license.id,{assignee_type:'group',assignee_id:groupId},context.actor.principal.userId,{});
 const target=await context.target();await context.worker().target(target.id);await context.worker().target(target.id);assert.equal(writes().length,1);
 context.allocator.groups.source.snapshot=async()=>{throw new Error('Owned group-only directory outage');};
 await pool.query("CREATE OR REPLACE FUNCTION license_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+interval '301 seconds'; $$");
 assert.equal((await pool.query('SELECT count(*)::int AS count FROM license_assignments')).rows[0].count,1);
 await context.worker().target(target.id);assert.equal((await context.target()).desired,false);assert.equal((await context.target()).status,'verifying');assert.equal(writes().length,2);
 assert.deepEqual(JSON.parse(writes()[1].body),{addLicenses:[],removeLicenses:[context.product.skuId]});
 await context.worker().target(target.id);assert.equal((await context.target()).status,'confirmed');assert.deepEqual(remote.assignedLicenses,[]);
});
test('an earlier explicit source-consent deadline reaches actual owned provider removal without a directory poll or local expiry sweep',async()=>{
 const context=await fixture({assign:false});const groupId=randomUUID();const deadline=new Date(Date.now()+60000).toISOString();
 context.allocator.groups.source.snapshot=async()=>groupSnapshot({groupId,memberIds:[context.subject.userId],sourceAuthorization:{grantId:randomUUID(),version:'1',issuer:'https://fulfillment.test',clientId:'owned-group-source',clientRevision:'1',expiresAt:deadline}});
 const proof=await context.allocator.groups.source.snapshot();context.allocator.groups.source.snapshot=async()=>proof;
 await context.allocator.assign(context.license.id,{assignee_type:'group',assignee_id:groupId},context.actor.principal.userId,{});assert.equal((await pool.query('SELECT expires_at FROM license_assignments WHERE license_id=$1',[context.license.id])).rows[0].expires_at.toISOString(),deadline);
 const target=await context.target();await context.worker().target(target.id);await context.worker().target(target.id);assert.equal(writes().length,1);
 context.allocator.groups.source.snapshot=async()=>{throw new Error('Owned group source offline');};await pool.query("CREATE OR REPLACE FUNCTION license_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+interval '61 seconds'; $$");
 await context.worker().target(target.id);assert.equal((await context.target()).desired,false);assert.equal((await context.target()).status,'verifying');assert.equal(writes().length,2);await context.worker().target(target.id);assert.equal((await context.target()).status,'confirmed');
});
test('bindings start paused, retain immutable namespace and exact versions, and cannot alias another local user to the same provider object',async()=>{
  const context=await fixture({ enable:false }); assert.equal((await context.target()).paused,true); await context.worker().sweep(); assert.equal(calls.length,0);
  await assert.rejects(context.store.enable('connectors',context.connector.id,'*',{ enabled:true,reason:'Stale wildcard must never enable cloud writes' },context.actor.user,context.actor.principal),error=>error.status===412);
  await assert.rejects(pool.query('UPDATE license_provider_subjects SET object_id=$2,version=version+1 WHERE id=$1',[context.subject.id,randomUUID()]));
  await assert.rejects(pool.query('DELETE FROM license_provider_products WHERE id=$1',[context.product.id]));
  await assert.rejects(context.store.create('subjects',{ connectorId:context.connector.id,userId:randomUUID(),objectId:context.subject.objectId,exclusiveDirectManagement:true,reason:'Explicit duplicate external identity denied' },context.actor.user,context.actor.principal,'Bearer owned-fixture'));
});
test('an ambiguous accepted write is never replayed or called provisioned; fresh explicit adoption is a separate protected duty',async()=>{
  const context=await fixture(); const target=await context.target();
  writeBehavior=async(req,res,body)=>{
    const entry=body.addLicenses[0]; remote.assignedLicenses=[entry]; remote.licenseAssignmentStates=[{ ...entry,assignedByGroup:null,state:'Active',error:null }]; req.socket.destroy();
  };
  await context.worker().target(target.id); assert.equal((await context.target()).status,'unknown'); assert.equal((await context.target()).owned,false);
  await context.worker().target(target.id); const unknown=await context.target(); assert.equal(unknown.status,'unknown'); assert.equal(unknown.canAdopt,true); assert.equal(writes().length,1);
  const operatorActor=operator(['license-fulfillment-operator']);
  await assert.rejects(context.store.resolve(target.id,'adopt',etag('targets',target.id,unknown.version),{ reason:'Operator cannot adopt unmanaged direct assignments',acknowledgeExclusiveManagement:true },operatorActor.user,operatorActor.principal),error=>error.status===403);
  await context.store.resolve(target.id,'adopt',etag('targets',target.id,unknown.version),{ reason:'Independent owner reviewed exclusive direct assignment',acknowledgeExclusiveManagement:true },context.actor.user,context.actor.principal);
  writeBehavior=null; await context.worker().target(target.id); assert.equal((await context.target()).status,'confirmed'); assert.equal(writes().length,1);
});
test('restart after committed write intent is conservatively unknown and retry needs an explicit uncertainty acknowledgement',async()=>{
  const context=await fixture(); const target=await context.target(); await context.store.writeIntent(await context.store.row(target.id),{ type:'owned-fixture-worker' });
  await context.worker().target(target.id); const unknown=await context.target(); assert.equal(unknown.status,'unknown'); assert.equal(writes().length,0);
  const actor=operator(['license-fulfillment-operator']); const reason='Reviewed isolated pre-dispatch crash and current desired state';
  await assert.rejects(context.store.resolve(target.id,'retry',etag('targets',target.id,unknown.version),{ reason,acknowledgeUncertainOutcome:false },actor.user,actor.principal),error=>error.status===409);
  await context.store.resolve(target.id,'retry',etag('targets',target.id,unknown.version),{ reason,acknowledgeUncertainOutcome:true },actor.user,actor.principal);
  await context.worker().target(target.id); assert.equal(writes().length,1);
});
test('a withdrawn uncertain add has a separately reviewed cleanup path, including for a now disabled canonical user',async()=>{
  const context=await fixture(); const target=await context.target(); writeBehavior=async(req,_res,body)=>{
    const entry=body.addLicenses[0]; remote.assignedLicenses=[entry]; remote.licenseAssignmentStates=[{ ...entry,assignedByGroup:null,state:'Active',error:null }]; req.socket.destroy();
  };
  await context.worker().target(target.id); assert.equal((await context.target()).status,'unknown');
  await context.allocator.revoke(context.license.id,context.subject.userId,context.actor.principal.userId,'user'); context.update({ enabled:false,revision:'2' });
  await context.worker().target(target.id); const review=await context.target(); assert.equal(review.adoptionPurpose,'cleanup'); assert.equal(review.canAdopt,true); assert.equal(writes().length,1);
  await context.store.resolve(target.id,'adopt',etag('targets',target.id,review.version),{ reason:'Independent review of withdrawn uncertain direct grant',acknowledgeExclusiveManagement:true },context.actor.user,context.actor.principal);
  writeBehavior=null; await context.worker().target(target.id); await context.worker().target(target.id);
  assert.equal((await context.target()).status,'confirmed'); assert.equal((await context.target()).desired,false); assert.equal(remote.assignedLicenses.length,0); assert.equal(writes().length,2);
  remote.assignedLicenses=[{ skuId:context.product.skuId,disabledPlans:[] }]; remote.licenseAssignmentStates=[{ skuId:context.product.skuId,disabledPlans:[],assignedByGroup:null,state:'Active',error:null }];
  await context.worker().target(target.id); const late=await context.target(); assert.equal(late.adoptionPurpose,'cleanup');
  await assert.rejects(pool.query('UPDATE license_fulfillment_targets SET uncertain_add_id=NULL WHERE id=$1',[target.id]));
});
test('directory outage cannot use a saved positive eligibility or make any Graph call',async()=>{
  const context=await fixture(); const target=await context.target(); context.identity.user=async()=>{ throw new Error('isolated source outage'); };
  await context.worker().target(target.id); assert.equal(calls.length,0); assert.equal((await context.target()).status,'failed'); assert.equal((await context.target()).error,'identity_source_unavailable');
});
test('a directory disablement during provider inspection is rechecked before any remote grant',async()=>{
  const context=await fixture(); const target=await context.target(); readBehavior=async()=>context.update({ enabled:false,revision:'2' });
  await context.worker().target(target.id); assert.equal(writes().length,0); assert.equal((await context.target()).desired,false);
  assert.equal((await pool.query('SELECT COUNT(*)::int AS count FROM license_assignments WHERE license_id=$1',[context.license.id])).rows[0].count,1);
});
test('a missed disable/reactivate incarnation cannot provision an earlier entitlement; a newly reviewed local grant can',async()=>{
  const context=await fixture(); const target=await context.target(); context.update({ enabled:true,revision:'3' });
  await context.worker().target(target.id); assert.equal((await context.target()).desired,false); assert.equal(writes().length,0);
  await context.allocator.revoke(context.license.id,context.subject.userId,context.actor.principal.userId,'user');
  await context.allocator.assign(context.license.id,{ assignee_type:'user',assignee_id:context.subject.userId },context.actor.principal.userId);
  await context.worker().target(target.id); assert.equal(writes().length,1);
});
test('Graph throttling defers the connector across fresh worker instances and cannot bypass its retry-after window',async()=>{
  const context=await fixture(); const target=await context.target(); writeBehavior=async(_req,res)=>{ res.statusCode=429; res.setHeader('Retry-After','3600'); res.end('{}'); };
  await context.worker().target(target.id); assert.equal((await context.target()).status,'pending'); const before=calls.length;
  await context.worker().target(target.id); await context.worker().sweep(); assert.equal(calls.length,before); assert.equal(writes().length,1);
});
test('a known authorization failure is not retried automatically or answered with broader Graph credentials',async()=>{
  const context=await fixture(); const target=await context.target(); writeBehavior=async(_req,res)=>{ res.statusCode=403; res.end('{}'); };
  await context.worker().target(target.id); assert.equal((await context.target()).status,'failed'); writeBehavior=null; await context.worker().target(target.id);
  assert.equal(writes().length,1); assert.equal((await context.target()).status,'failed');
});
test('an explicit provider assignment error is a failure, yet its known owned direct assignment can still be removed',async()=>{
  const context=await fixture(); const target=await context.target(); await context.worker().target(target.id);
  remote.licenseAssignmentStates[0].state='Error'; remote.licenseAssignmentStates[0].error='CountViolation';
  await context.worker().target(target.id); assert.equal((await context.target()).status,'failed'); assert.equal((await context.target()).error,'graph_assignment_error'); assert.equal(writes().length,1);
  await context.allocator.revoke(context.license.id,context.subject.userId,context.actor.principal.userId,'user'); await context.worker().target(target.id); await context.worker().target(target.id);
  assert.equal((await context.target()).status,'confirmed'); assert.equal(remote.assignedLicenses.length,0);
});
test('expiry between a reviewed observation and adoption cannot acquire foreign license ownership',async()=>{
  const context=await fixture(); const target=await context.target(); remote.assignedLicenses=[{ skuId:context.product.skuId,disabledPlans:[] }]; remote.licenseAssignmentStates=[{ skuId:context.product.skuId,disabledPlans:[],assignedByGroup:null,state:'Active',error:null }];
  await context.worker().target(target.id);
  await context.allocator.transaction(async client=>{
    await client.query("UPDATE license_assignment_sources SET expires_at=date_trunc('milliseconds',clock_timestamp())+interval '200 milliseconds' WHERE license_id=$1",[context.license.id]);
    await context.allocator.syncUser(client,context.license.id,context.subject.userId,context.actor.principal.userId);
  });
  const before=await context.target(); await new Promise(resolve=>setTimeout(resolve,300));
  assert.equal((await context.target()).canAdopt,false);
  await assert.rejects(context.store.resolve(target.id,'adopt',etag('targets',target.id,before.version),{ reason:'Expired local approval cannot adopt a vendor license',acknowledgeExclusiveManagement:true },context.actor.user,context.actor.principal),error=>error.status===412);
  assert.equal((await context.target()).owned,false); assert.equal(writes().length,0);
});
test('outbox loss rolls back the local seat/source transaction instead of silently losing provisioning work',async()=>{
  const context=await fixture({ assign:false }); await pool.query('ALTER TABLE license_fulfillment_changes RENAME TO withheld_fulfillment_changes');
  try { await assert.rejects(context.allocator.assign(context.license.id,{ assignee_type:'user',assignee_id:context.subject.userId },context.actor.principal.userId)); }
  finally { await pool.query('ALTER TABLE withheld_fulfillment_changes RENAME TO license_fulfillment_changes'); }
  assert.equal((await pool.query('SELECT used_seats FROM license_catalog WHERE id=$1',[context.license.id])).rows[0].used_seats,0);
  assert.equal((await pool.query('SELECT COUNT(*)::int AS count FROM license_assignments WHERE license_id=$1',[context.license.id])).rows[0].count,0);
});
test('audit failure after a real remote effect leaves an unfinished intent, never a false success',async()=>{
  const context=await fixture(); const target=await context.target(); writeBehavior=async()=>{ await pool.query('ALTER TABLE license_fulfillment_events RENAME TO withheld_fulfillment_events'); };
  try { await assert.rejects(context.worker().target(target.id)); }
  finally { await pool.query('ALTER TABLE withheld_fulfillment_events RENAME TO license_fulfillment_events'); writeBehavior=null; }
  assert.equal((await context.target()).status,'in_flight'); assert.equal(remote.assignedLicenses.length,1);
  await context.worker().target(target.id); assert.equal((await context.target()).status,'unknown'); assert.equal((await context.target()).owned,false); assert.equal(writes().length,1);
});
test('a superseded remote receipt cannot confirm a newer withdrawn desired state; the next worker compensates the known owned add',async()=>{
  const context=await fixture(); const target=await context.target(); writeBehavior=async()=>{ await context.allocator.revoke(context.license.id,context.subject.userId,context.actor.principal.userId,'user'); };
  await context.worker().target(target.id); const changed=await context.target(); assert.equal(changed.desired,false); assert.equal(changed.status,'pending'); assert.equal(changed.owned,true);
  writeBehavior=null; await context.worker().target(target.id); await context.worker().target(target.id); assert.equal((await context.target()).status,'confirmed'); assert.equal(remote.assignedLicenses.length,0);
});
test('independent workers serialize a target with a real database advisory lock',async()=>{
  const context=await fixture(); const target=await context.target(); let release; let enter; const entered=new Promise(resolve=>{ enter=resolve; }); const blocked=new Promise(resolve=>{ release=resolve; });
  readBehavior=async()=>{ enter(); await blocked; }; const first=context.worker().target(target.id); await entered;
  await context.worker().target(target.id); release(); await first; assert.equal(writes().length,1);
});
test('stopping a worker during inspection prevents follow-up cloud writes and releases its session lock',async()=>{
  const context=await fixture(); const target=await context.target(); const worker=context.worker(); readBehavior=async()=>worker.stop();
  await worker.target(target.id); assert.equal(writes().length,0); readBehavior=null; await context.worker().target(target.id); assert.equal(writes().length,1);
});
for (const scenario of ['unmanaged','group','changed-plans']) test('existing '+scenario+' assignments are observed, never overwritten or removed implicitly',async()=>{
  const context=await fixture(); const target=await context.target(); const disabledPlans=scenario==='changed-plans'?[randomUUID()]:[];
  remote.assignedLicenses=[{ skuId:context.product.skuId,disabledPlans }]; remote.licenseAssignmentStates=[{ skuId:context.product.skuId,disabledPlans,assignedByGroup:scenario==='group'?randomUUID():null,state:'Active',error:null }];
  await context.worker().target(target.id); assert.equal((await context.target()).status,'conflict'); assert.equal(writes().length,0);
  if (scenario!=='unmanaged') assert.equal((await context.target()).canAdopt,false);
});
test('time expiry is reconsidered without depending on the local lifecycle worker timer',async()=>{
  const context=await fixture(); const target=await context.target(); await context.worker().target(target.id); await context.worker().target(target.id);
  await context.allocator.transaction(async client=>{
    await client.query("UPDATE license_assignment_sources SET expires_at=date_trunc('milliseconds',clock_timestamp())+interval '500 milliseconds' WHERE license_id=$1",[context.license.id]);
    await context.allocator.syncUser(client,context.license.id,context.subject.userId,context.actor.principal.userId);
  });
  await new Promise(resolve=>setTimeout(resolve,600)); await context.worker().target(target.id); assert.equal((await context.target()).desired,false); assert.equal(writes().length,2);
});
test('migration reapplication preserves desired generations, provider ownership and immutable evidence',async()=>{
  const context=await fixture(); const target=await context.target(); await context.worker().target(target.id); await context.worker().target(target.id); const before=await context.target();
  await pool.query(fs.readFileSync(path.join(__dirname,'../../db/migrations/009_license_fulfillment.sql'),'utf8')); assert.deepEqual(await context.target(),before);
  const event=(await pool.query('SELECT id FROM license_fulfillment_events LIMIT 1')).rows[0]; const change=(await pool.query('SELECT id FROM license_fulfillment_changes LIMIT 1')).rows[0];
  for (const [table,id] of [['license_fulfillment_events',event.id],['license_fulfillment_changes',change.id]]) {
    await assert.rejects(pool.query('DELETE FROM '+table+' WHERE id=$1',[id]));
    await assert.rejects(pool.query('UPDATE '+table+' SET created_at=clock_timestamp() WHERE id=$1',[id]));
  }
  await assert.rejects(pool.query('UPDATE license_fulfillment_targets SET version=version-1 WHERE id=$1',[target.id]));
});

async function anotherTarget(context){
 const userId=randomUUID();const reason='Explicit independently mapped second capacity recipient';
 let subject=await context.store.create('subjects',{connectorId:context.connector.id,userId,objectId:randomUUID(),exclusiveDirectManagement:true,reason},context.actor.user,context.actor.principal);
 subject=await context.store.enable('subjects',subject.id,etag('subjects',subject.id,subject.version),{enabled:true,reason},context.actor.user,context.actor.principal);
 await context.allocator.assign(context.license.id,{assignee_type:'user',assignee_id:userId},context.actor.principal.userId);
 return context.store.row((await context.store.lookup(context.license.id,userId,context.actor.user)).id);
}
const admissionCount=async(table='license_capacity_reservations')=>(await pool.query(`SELECT count(*)::int AS count FROM ${table}`)).rows[0].count;
const intent=async(context,row)=>context.store.writeIntent(row||await context.store.row((await context.target()).id),{type:'owned-capacity-worker'});
test('new vendor additions default-deny without both current inventory and an independently reviewed budget, without removing local rights',async()=>{
 const context=await fixture({capacityReview:false});const target=await context.target();await context.worker().target(target.id);
 assert.equal(writes().length,0);assert.equal((await context.target()).error,'capacity_budget_required');assert.equal(await admissionCount(),0);
 await context.capacity.capture();await context.worker().target(target.id);assert.equal(writes().length,0);assert.equal((await context.target()).error,'capacity_budget_required');
 assert.equal((await pool.query('SELECT used_seats FROM license_catalog WHERE id=$1',[context.license.id])).rows[0].used_seats,1);
 await context.capacity.approve();await context.worker().target(target.id);assert.equal(writes().length,1);assert.equal(await admissionCount(),1);
});
test('two independently locked recipients cannot spend the same finite capacity unit in concurrent actual SQL write intents',async()=>{
 const context=await fixture({capacityUnits:1});const first=await context.store.row((await context.target()).id);const second=await anotherTarget(context);
 const attempts=await Promise.allSettled([intent(context,first),intent(context,second)]);assert.equal(attempts.filter(result=>result.status==='fulfilled').length,1);
 assert.equal(attempts.find(result=>result.status==='rejected').reason.message,'capacity_admission_exhausted');assert.equal(await admissionCount(),1);
 assert.equal((await pool.query("SELECT count(*)::int AS count FROM license_fulfillment_events WHERE action='write-intent'")).rows[0].count,1);
 assert.equal((await pool.query("SELECT count(*)::int AS count FROM license_capacity_admission_outbox WHERE action='capacity-reserved'")).rows[0].count,1);assert.equal(writes().length,0);
});
test('a configured local pool or unlimited convention cannot expand a zero reviewed manufacturer quota',async()=>{
 const context=await fixture({capacityUnits:0});await pool.query('UPDATE license_catalog SET total_seats=0 WHERE id=$1',[context.license.id]);await context.worker().target((await context.target()).id);
 assert.equal(writes().length,0);assert.equal((await context.target()).error,'capacity_admission_exhausted');assert.equal(await admissionCount(),0);
});
test('a newer failed or checking capture and physical inventory expiry supersede positive capacity before admission',async()=>{
 const context=await fixture();const valid=context.capacity.sku.appliesTo;context.capacity.sku.appliesTo='invalid';assert.equal((await context.capacity.capture()).status,'failed');
 await assert.rejects(intent(context),error=>error.message==='capacity_observation_required');context.capacity.sku.appliesTo=valid;await context.capacity.capture();
 const source=(await context.capacity.restricted.query('SELECT license_capacity_source($1) AS source',[context.capacity.sourceId])).rows[0].source;
 await context.capacity.restricted.query('INSERT INTO license_capacity_runs(id,source_id,source_version,connector_version) VALUES($1,$2,$3,$4)',[randomUUID(),source.sourceId,source.sourceVersion,source.connectorVersion]);
 await assert.rejects(intent(context),error=>error.message==='capacity_observation_required');await context.capacity.capture();
 await pool.query("CREATE OR REPLACE FUNCTION license_capacity_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+interval '301 seconds'; $$");
 await assert.rejects(intent(context),error=>error.message==='capacity_observation_required');assert.equal(await admissionCount(),0);
});
test('company, suspended and missing SKUs cannot be admitted through an older reviewed user-product budget',async()=>{
 const context=await fixture();for(const patch of [{appliesTo:'Company'},{appliesTo:'User',capabilityStatus:'Suspended'},{capabilityStatus:'Enabled',skuId:randomUUID()}]){
  Object.assign(context.capacity.sku,patch);assert.equal((await context.capacity.capture()).status,'complete');await assert.rejects(intent(context),error=>error.message==='capacity_enabled_user_sku_required');
 }assert.equal(await admissionCount(),0);
});
test('source withdrawal after intent rejects actual dispatch without refunding or reusing its retained capacity charge',async()=>{
 const context=await fixture({capacityUnits:1});const row=await context.store.row((await context.target()).id);const attempt=await intent(context,row);
 await context.allocator.transaction(async client=>{await client.query("SELECT set_config('opendirectory.capacity_source_reason','Independent source withdrawal after durable intent',true)");await client.query('UPDATE license_capacity_sources SET enabled=false,version=version+1 WHERE id=$1',[context.capacity.sourceId]);});
 assert.equal(await context.store.dispatch(row,attempt),false);assert.equal(await admissionCount(),1);assert.equal(writes().length,0);
 await context.allocator.transaction(async client=>{await client.query("SELECT set_config('opendirectory.capacity_source_reason','Explicit source reissue does not revive old budget',true)");await client.query('UPDATE license_capacity_sources SET enabled=true,version=version+1 WHERE id=$1',[context.capacity.sourceId]);});
 await context.capacity.capture();assert.equal(await context.store.dispatch(row,attempt),false);await assert.rejects(intent(context),error=>error.message==='capacity_binding_review_required');
});
test('local withdrawal between committed intent and actual dispatch cannot send an obsolete addition',async()=>{
 const context=await fixture();const row=await context.store.row((await context.target()).id);const attempt=await intent(context,row);await context.allocator.revoke(context.license.id,context.subject.userId,context.actor.principal.userId,'user');
 assert.equal(await context.store.dispatch(row,attempt),false);assert.equal((await context.target()).desired,false);assert.equal(await admissionCount(),1);assert.equal(writes().length,0);
});
test('a dispatch receipt is short lived, single use, generation bound and never an automatic refund after timeout',async()=>{
 const context=await fixture();const row=await context.store.row((await context.target()).id);const attempt=await intent(context,row);
 const decisions=await Promise.all([context.store.dispatch(row,attempt),context.store.dispatch(row,attempt)]);assert.deepEqual(decisions.sort(),[false,true]);assert.equal(await context.store.dispatch(row,attempt),false);
 assert.equal((await pool.query("SELECT count(*)::int AS count FROM license_capacity_admission_events WHERE action='dispatch-admitted'")).rows[0].count,1);
 await pool.query("CREATE OR REPLACE FUNCTION license_capacity_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+interval '11 seconds'; $$");
 assert.equal(await context.store.dispatch(row,attempt),false);assert.equal(await admissionCount(),1);
});
test('capacity evidence loss rolls back the actual write intent and never acknowledges a reserved unit',async()=>{
 for(const table of ['license_capacity_admission_events','license_capacity_admission_outbox']){
  const context=await fixture();const before=(await context.target()).status;await pool.query(`ALTER TABLE ${table} RENAME TO owned_missing_capacity_admission`);
  try{await assert.rejects(intent(context));}finally{await pool.query(`ALTER TABLE owned_missing_capacity_admission RENAME TO ${table}`);}
  assert.equal((await context.target()).status,before);assert.equal(await admissionCount(),0);
 }assert.equal(writes().length,0);
});
test('dispatch evidence loss cannot consume a one-time receipt or permit a provider POST',async()=>{
 const context=await fixture();const row=await context.store.row((await context.target()).id);const attempt=await intent(context,row);
 await pool.query('ALTER TABLE license_capacity_admission_outbox RENAME TO owned_missing_dispatch_outbox');
 try{await assert.rejects(context.store.dispatch(row,attempt));}finally{await pool.query('ALTER TABLE owned_missing_dispatch_outbox RENAME TO license_capacity_admission_outbox');}
 assert.equal((await pool.query('SELECT dispatched_at FROM license_capacity_reservations WHERE attempt_id=$1',[attempt])).rows[0].dispatched_at,null);assert.equal(writes().length,0);
 assert.equal(await context.store.dispatch(row,attempt),true);
});
test('a known admission cutoff reached behind actual audit DML rolls back at deferred commit',async()=>{
 const context=await fixture();await pool.query('CREATE TABLE owned_admission_clock(seconds integer NOT NULL);INSERT INTO owned_admission_clock VALUES(0)');
 await pool.query(`CREATE OR REPLACE FUNCTION license_capacity_now() RETURNS timestamptz LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=${schema},pg_catalog,pg_temp AS $$ SELECT clock_timestamp()+seconds*interval '1 second' FROM owned_admission_clock; $$`);
 await pool.query("CREATE FUNCTION owned_admission_clock_advance() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='capacity-reserved' THEN UPDATE owned_admission_clock SET seconds=11;END IF;RETURN NEW;END;$$;CREATE TRIGGER owned_admission_clock_advance AFTER INSERT ON license_capacity_admission_events FOR EACH ROW EXECUTE FUNCTION owned_admission_clock_advance()");
 try{await assert.rejects(intent(context),error=>error.message==='capacity_dispatch_admission_changed');assert.equal(await admissionCount(),0);assert.equal((await context.target()).status,'pending');}
 finally{await pool.query('DROP TRIGGER owned_admission_clock_advance ON license_capacity_admission_events;DROP FUNCTION owned_admission_clock_advance();CREATE OR REPLACE FUNCTION license_capacity_now() RETURNS timestamptz LANGUAGE sql VOLATILE SECURITY INVOKER AS $$ SELECT clock_timestamp(); $$;DROP TABLE owned_admission_clock');}
});
test('an uncertain actual provider write remains charged across captures, restarts and ordinary review retries',async()=>{
 const context=await fixture({capacityUnits:1});const target=await context.target();writeBehavior=async(_request,response)=>response.destroy();await context.worker().target(target.id);
 assert.equal((await context.target()).status,'unknown');assert.equal(await admissionCount(),1);await context.capacity.capture();await assert.rejects(context.capacity.approve(),/Unfinished or unobserved/);
 await context.worker().target(target.id);assert.equal(writes().length,1);assert.equal(await admissionCount(),1);
});
test('successful observation does not refill a quota; only explicit conditional review of a later inventory can start a new budget',async()=>{
 const context=await fixture({capacityUnits:2});const target=await context.target();await context.worker().target(target.id);await context.worker().target(target.id);assert.equal((await context.target()).status,'confirmed');
 context.capacity.sku.consumedUnits=1;await context.capacity.capture();assert.equal(await admissionCount('license_capacity_budgets'),1);
 const budget=await context.capacity.approve();assert.equal(budget.units,1);assert.equal(await admissionCount('license_capacity_budgets'),2);assert.equal(await admissionCount(),1);
 await assert.rejects(context.capacity.approve({previous_budget_id:''}),/conditional/);
});
test('withdrawal still removes a known owned assignment when inventory is unavailable and its quota is exhausted',async()=>{
 const context=await fixture({capacityUnits:1});const target=await context.target();await context.worker().target(target.id);await context.worker().target(target.id);
 context.capacity.sku.appliesTo='invalid';await context.capacity.capture();await context.allocator.revoke(context.license.id,context.subject.userId,context.actor.principal.userId,'user');
 await context.worker().target(target.id);await context.worker().target(target.id);assert.equal(writes().length,2);assert.equal((await context.target()).status,'confirmed');assert.equal((await context.target()).desired,false);assert.equal(await admissionCount(),1);
});
test('raw SQL cannot fabricate a budget, erase charges, forge dispatch evidence or use the old write protocol',async()=>{
 const context=await fixture();const row=await context.store.row((await context.target()).id);
 await assert.rejects(pool.query("UPDATE license_fulfillment_targets SET status='in_flight',attempt_id=gen_random_uuid(),attempt_desired=desired,attempt_version=version WHERE id=$1",[row.id]),error=>error.message==='capacity_worker_upgrade_required');
 const attempt=await intent(context,row);for(const sql of ['DELETE FROM license_capacity_reservations','UPDATE license_capacity_reservations SET reserved_at=clock_timestamp()',
  'DELETE FROM license_capacity_budgets','UPDATE license_capacity_budgets SET units=2147483647',"INSERT INTO license_capacity_admission_events(budget_id,action,actor,details) SELECT id,'fake','{}','{}' FROM license_capacity_budgets"])
  await assert.rejects(pool.query(sql),error=>error.code==='42501');
 for(const sql of ['SELECT * FROM license_capacity_reservations','SELECT * FROM license_capacity_budgets','SELECT license_capacity_dispatch($1,$2)'])await assert.rejects(context.capacity.restricted.query(sql,sql.includes('$1')?[attempt,row.id]:undefined),error=>error.code==='42501');
});
test('migration replay retains admission generations, receipts, charges and known cutoffs without restamping',async()=>{
 const context=await fixture();const row=await context.store.row((await context.target()).id);const attempt=await intent(context,row);await context.store.dispatch(row,attempt);
 const before=(await pool.query('SELECT * FROM license_capacity_reservations')).rows;const budgets=(await pool.query('SELECT * FROM license_capacity_budgets')).rows;
 await pool.query(fs.readFileSync(path.join(__dirname,'../../db/migrations/021_license_capacity_admission.sql'),'utf8'));
 assert.deepEqual((await pool.query('SELECT * FROM license_capacity_reservations')).rows,before);assert.deepEqual((await pool.query('SELECT * FROM license_capacity_budgets')).rows,budgets);assert.equal(await context.store.dispatch(row,attempt),false);
});
test('an actual worker cannot POST after its collector source is withdrawn between intent commit and dispatch',async()=>{
 const context=await fixture();const original=context.store.writeIntent.bind(context.store);context.store.writeIntent=async(...args)=>{
  const attempt=await original(...args);await context.allocator.transaction(async client=>{await client.query("SELECT set_config('opendirectory.capacity_source_reason','Independent withdrawal at the actual pre-POST boundary',true)");await client.query('UPDATE license_capacity_sources SET enabled=false,version=version+1 WHERE id=$1',[context.capacity.sourceId]);});return attempt;
 };
 await context.worker().target((await context.target()).id);assert.equal(writes().length,0);assert.equal((await context.target()).status,'unknown');assert.equal((await context.target()).error,'capacity_dispatch_not_admitted');assert.equal(await admissionCount(),1);
});
test('pending additions remain uncovered after a new capture until a separate successful user observation precedes that capture',async()=>{
 const context=await fixture({capacityUnits:2});const target=await context.target();await context.worker().target(target.id);const second=await anotherTarget(context);
 context.capacity.sku.consumedUnits=1;await context.capacity.capture();await assert.rejects(intent(context,second),error=>error.message==='capacity_admission_exhausted');
 await context.worker().target(target.id);await context.capacity.capture();assert.ok(await intent(context,second));assert.equal(await admissionCount(),2);assert.equal(await admissionCount('license_capacity_budgets'),1);
});
test('budget review and dispatch each recheck their own physical cutoffs after mandatory audit DML',async()=>{
 const context=await fixture({capacityReview:false});await context.capacity.capture();await pool.query('CREATE TABLE owned_budget_clock(seconds integer NOT NULL);INSERT INTO owned_budget_clock VALUES(0)');
 await pool.query(`CREATE OR REPLACE FUNCTION license_capacity_now() RETURNS timestamptz LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=${schema},pg_catalog,pg_temp AS $$ SELECT clock_timestamp()+seconds*interval '1 second' FROM owned_budget_clock; $$`);
 await pool.query("CREATE FUNCTION owned_budget_clock_advance() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN UPDATE owned_budget_clock SET seconds=CASE WHEN NEW.action='budget-reviewed' THEN 301 WHEN NEW.action='dispatch-admitted' THEN 11 ELSE 0 END;RETURN NEW;END;$$;CREATE TRIGGER owned_budget_clock_advance AFTER INSERT ON license_capacity_admission_events FOR EACH ROW EXECUTE FUNCTION owned_budget_clock_advance()");
 try{
  await assert.rejects(context.capacity.approve(),/expired before commit/);assert.equal(await admissionCount('license_capacity_budgets'),0);
  await pool.query('ALTER TABLE license_capacity_admission_events DISABLE TRIGGER owned_budget_clock_advance');await context.capacity.approve();const row=await context.store.row((await context.target()).id);const attempt=await intent(context,row);await pool.query('ALTER TABLE license_capacity_admission_events ENABLE TRIGGER owned_budget_clock_advance');
  await assert.rejects(context.store.dispatch(row,attempt),error=>error.message==='capacity_dispatch_admission_changed');assert.equal((await pool.query('SELECT dispatched_at FROM license_capacity_reservations WHERE attempt_id=$1',[attempt])).rows[0].dispatched_at,null);assert.equal(await admissionCount(),1);
 }finally{await pool.query('DROP TRIGGER owned_budget_clock_advance ON license_capacity_admission_events;DROP FUNCTION owned_budget_clock_advance();CREATE OR REPLACE FUNCTION license_capacity_now() RETURNS timestamptz LANGUAGE sql VOLATILE SECURITY INVOKER AS $$ SELECT clock_timestamp(); $$;DROP TABLE owned_budget_clock');}
});
test('the actual local entitlement expiry caps an undispatched receipt without waiting for a lifecycle sweep',async()=>{
 const context=await fixture();await context.allocator.transaction(async client=>{
  await client.query("UPDATE license_assignment_sources SET expires_at=date_trunc('milliseconds',clock_timestamp())+interval '250 milliseconds' WHERE license_id=$1",[context.license.id]);
  await context.allocator.syncUser(client,context.license.id,context.subject.userId,context.actor.principal.userId);
 });
 const row=await context.store.row((await context.target()).id);const attempt=await intent(context,row);const receipt=(await pool.query('SELECT dispatch_before FROM license_capacity_reservations WHERE attempt_id=$1',[attempt])).rows[0];
 const cutoff=(await pool.query('SELECT expires_at FROM license_assignments WHERE license_id=$1',[context.license.id])).rows[0].expires_at;assert.equal(receipt.dispatch_before.getTime(),cutoff.getTime());
 await new Promise(resolve=>setTimeout(resolve,300));assert.equal(await context.store.dispatch(row,attempt),false);assert.equal(await admissionCount(),1);assert.equal(writes().length,0);
});
test('product and connector pause/reissue cannot reuse an earlier admission generation or receipt',async()=>{
 for(const kind of ['products','connectors']){
  const context=await fixture();const row=await context.store.row((await context.target()).id);const attempt=await intent(context,row);let binding=await context.store.get(kind,kind==='products'?context.product.id:context.connector.id);
  for(const enabled of [false,true])binding=await context.store.enable(kind,binding.id,etag(kind,binding.id,binding.version),{enabled,reason:'Explicit reviewed provider generation reissue after intent'},context.actor.user,context.actor.principal);
  assert.equal(await context.store.dispatch(row,attempt),false);await context.capacity.capture();await assert.rejects(intent(context),error=>error.message==='capacity_binding_review_required');
 }assert.equal(writes().length,0);
});
test('stopping an actual worker during receiving SQL admission prevents a later POST even after the receipt committed',async()=>{
 const context=await fixture();const worker=context.worker();const original=context.store.dispatch.bind(context.store);
 context.store.dispatch=async(...args)=>{const admitted=await original(...args);assert.equal(admitted,true);worker.stop();return admitted;};
 await worker.target((await context.target()).id);assert.equal(writes().length,0);assert.equal((await context.target()).status,'unknown');assert.equal((await context.target()).error,'capacity_dispatch_stopped');assert.equal(await admissionCount(),1);
 assert.notEqual((await pool.query('SELECT dispatched_at FROM license_capacity_reservations')).rows[0].dispatched_at,null);
});
