'use strict';
const {test,beforeEach,afterEach}=require('node:test');const assert=require('node:assert/strict');const {randomUUID}=require('node:crypto');
const fs=require('node:fs');const path=require('node:path');const {Pool}=require('pg');
const {ClientRegistry,etag}=require('../ClientRegistry');const {CompanyApps}=require('../CompanyApps');const contract=require('../../../../../packages/company-app-contract');const {hashSecret}=require('../clientSecrets');
let admin;let pool;let schema;let registry;let apps;let user;let proof;let tenant;let database;
const input=()=>({requestId:randomUUID(),name:'Own automation application',purpose:'none',reason:'Create a real tenant-owned app account',confirm:true});
beforeEach(async()=>{
 schema='company_apps_'+randomUUID().replaceAll('-','');admin=new Pool({connectionString:process.env.OAUTH_TEST_DATABASE_URL,max:1});await admin.query('CREATE SCHEMA '+schema);
 const url=new URL(process.env.OAUTH_TEST_DATABASE_URL);url.searchParams.set('options','-c search_path='+schema+',public');pool=new Pool({connectionString:url.toString(),max:5});
 const directory=path.join(__dirname,'../../migrations');for(const file of fs.readdirSync(directory).filter(name=>name.endsWith('.sql')).sort())await pool.query(fs.readFileSync(path.join(directory,file),'utf8'));
 const now=Math.floor(Date.now()/1000);tenant={id:randomUUID(),version:'1',generation:'2'};
 user={actor_type:'user',iss:'https://company-apps.test',sub:'actual-roleless-owner',jti:randomUUID(),exp:now+600,auth_time:now,identity_authorization:{userId:randomUUID(),revision:'1',linkRevision:'2',rolesRevision:'a'.repeat(64)}};
 proof={schemaVersion:1,companyAppProtocol:1,issuer:user.iss,subject:user.sub,tokenId:user.jti,expiresAt:user.exp,context:user.identity_authorization,tenant,actorUserId:user.identity_authorization.userId,permissions:[...contract.PERMISSIONS],validUntil:now+300};
 database={isAvailable:()=>true,pool};registry=new ClientRegistry(database,{companyTenantActive:async()=>true});apps=new CompanyApps(registry);apps.authority=async()=>contract.source(proof,user);
});
afterEach(async()=>{await pool?.end();await admin?.query('DROP SCHEMA IF EXISTS '+schema+' CASCADE');await admin?.end();});
const create=async(body=input())=>apps.create(body,user,'Bearer original-owner');
const update=async(row,change={})=>apps.mutate(row.clientId,etag(row),{name:row.name,enabled:row.enabled,purpose:row.purpose,reason:'Explicitly change the original own app',confirm:true,...change},user,'Bearer original-owner');
test('roleless ownership creates one disabled canonical client with a hashed secret and atomic original event/outbox',async()=>{
 const result=await create();assert.equal(result.client.enabled,false);assert.equal(result.client.purpose,'none');assert.equal(result.created,true);assert.equal(result.actorUserId,proof.actorUserId);
 const row=(await pool.query('SELECT * FROM oauth_clients WHERE id=$1',[result.client.clientId])).rows[0];assert.equal(row.secret,null);assert.equal(row.secret_hash,hashSecret(result.clientSecret));assert.deepEqual(row.company_tenant,tenant);
 const audit=(await pool.query('SELECT * FROM oauth_client_audit')).rows[0];assert.equal(audit.actor_user_id,proof.actorUserId);assert.equal(audit.details.source.tokenId,user.jti);assert.equal(audit.details.snapshot.secret_hash,undefined);
 assert.equal((await pool.query('SELECT count(*) AS n FROM oauth_company_app_outbox')).rows[0].n,'1');assert.equal(await registry.current(await registry.get(row.id)),false);
 const listed=await apps.list({},user,'Bearer original-owner');assert.equal(listed.clients.length,1);assert.ok(!JSON.stringify(listed).includes(result.clientSecret));assert.ok(!JSON.stringify(audit).includes(row.secret_hash));
});
test('a repeated original creation recovers the same app without returning the original secret or accepting changed intent',async()=>{
 const request=input();const first=await create(request);const recovered=await create(request);assert.equal(recovered.client.clientId,first.client.clientId);assert.equal(recovered.created,false);assert.equal(recovered.clientSecret,null);
 await assert.rejects(create({...request,purpose:'company-automation'}),{status:409});assert.equal((await pool.query('SELECT count(*) AS n FROM oauth_clients')).rows[0].n,'1');
});
test('two actual writers cannot acknowledge different versions of one original client',async()=>{
 const original=(await create()).client;const results=await Promise.allSettled([update(original,{enabled:true}),update(original,{name:'Concurrent renamed app'})]);
 assert.equal(results.filter(row=>row.status==='fulfilled').length,1);assert.equal(results.find(row=>row.status==='rejected').reason.status,412);assert.equal((await registry.get(original.clientId)).version,'2');
 assert.equal((await pool.query('SELECT count(*) AS n FROM oauth_client_audit WHERE client_id=$1',[original.clientId])).rows[0].n,'2');
});
test('rotation invalidates the previous actual secret and client generation and preserves the fixed company purpose',async()=>{
 const original=await create({...input(),purpose:'company-automation'});const enabled=await update(original.client,{enabled:true});const payload={actor_type:'application',client_id:enabled.client.clientId,client_revision:enabled.client.version,company_tenant:tenant};
 assert.equal(await registry.active(payload),true);assert.equal(await registry.active({...payload,company_tenant:undefined}),false);
 const rotated=await apps.mutate(enabled.client.clientId,etag(enabled.client),{reason:'Replace the original company app credential',confirm:true},user,'Bearer original-owner','rotated');
 assert.equal(await registry.active(payload),false);const record=await registry.get(rotated.client.clientId);assert.equal(registry.authenticated(record,original.clientSecret),false);assert.equal(registry.authenticated(record,rotated.clientSecret),true);assert.equal(rotated.client.purpose,'company-automation');
});
test('known foreign UUIDs cannot be read, updated, rotated, deleted or attached to another company',async()=>{
 const original=await create();const actual=proof;tenant={id:randomUUID(),version:'1',generation:'3'};proof={...actual,tenant};
 assert.equal((await apps.list({},user,'Bearer original-owner')).clients.length,0);
 await assert.rejects(apps.read(original.client.clientId,user,'Bearer original-owner'),{status:404});
 for(const action of ['rotated','deleted'])await assert.rejects(apps.mutate(original.client.clientId,etag(original.client),{reason:'This is an attempted foreign client operation',confirm:true},user,'Bearer original-owner',action),{status:404});
 await assert.rejects(update(original.client),{status:404});assert.deepEqual((await pool.query('SELECT company_tenant FROM oauth_clients')).rows[0].company_tenant,actual.tenant);
});
test('global registry permissions cannot read or modify a company-owned record through legacy routes',async()=>{
 const created=await create();const actor={...user,roles:['admin']};assert.deepEqual((await registry.list(actor)).clients,[]);
 await assert.rejects(registry.mutate(created.client.clientId,etag(created.client),{enabled:true},actor),{status:404});await assert.rejects(registry.authentication(created.client.clientId,actor),{status:404});
 await assert.rejects(registry.setAuthentication(created.client.clientId,etag(created.client),{required:true,maxAgeSeconds:300,reason:'A forbidden generic client policy change'},actor),{status:404});
});
test('an unavailable or withdrawn original authority before commit rolls back the actual credential, event and outbox',async()=>{
 let calls=0;apps.authority=async()=>{if(++calls===2)contract.fail(401,'original_source_withdrawn');return proof;};await assert.rejects(create(),{status:401});
 for(const table of ['oauth_clients','oauth_client_audit','oauth_company_app_outbox'])assert.equal((await pool.query('SELECT count(*) AS n FROM '+table)).rows[0].n,'0');
});
test('silently suppressing the original pending outbox prevents a successful canonical client creation',async()=>{
 await pool.query("CREATE FUNCTION suppress_company_box() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL;END; $$");await pool.query('CREATE TRIGGER zz_suppress_company_box BEFORE INSERT ON oauth_company_app_outbox FOR EACH ROW EXECUTE FUNCTION suppress_company_box()');
 await assert.rejects(create(),{status:503});for(const table of ['oauth_clients','oauth_client_audit','oauth_company_app_outbox'])assert.equal((await pool.query('SELECT count(*) AS n FROM '+table)).rows[0].n,'0');
});
test('company evidence and namespace are immutable and incomplete receiving fails closed',async()=>{
 const created=await create();await assert.rejects(pool.query("UPDATE oauth_clients SET company_tenant=jsonb_set(company_tenant,'{id}',to_jsonb($2::text)),revision=revision+1 WHERE id=$1",[created.client.clientId,randomUUID()]));
 await assert.rejects(pool.query('DELETE FROM oauth_company_app_outbox'),{code:'42501'});await assert.rejects(pool.query('TRUNCATE oauth_client_audit CASCADE'),{code:'42501'});
 await pool.query('ALTER TABLE oauth_clients DISABLE TRIGGER oauth_company_app_commit');await assert.rejects(apps.read(created.client.clientId,user,'Bearer original-owner'),{status:503});
});
test('soft deletion retains own metadata and history, disables authentication and cannot be undone by a new update',async()=>{
 const created=await create();const enabled=await update(created.client,{enabled:true});const deleted=await apps.mutate(enabled.client.clientId,etag(enabled.client),{reason:'Retire the original own company application',confirm:true},user,'Bearer original-owner','deleted');
 assert.equal(deleted.client.enabled,false);assert.ok(deleted.client.deletedAt);assert.equal(await registry.get(created.client.clientId),null);assert.equal((await apps.list({},user,'Bearer original-owner')).clients.length,0);
 const history=await apps.history(created.client.clientId,{},user,'Bearer original-owner');assert.deepEqual(history.events.map(row=>row.action),['deleted','updated','created']);await assert.rejects(update(deleted.client,{enabled:true}),{status:409});
});
test('actual machine admission follows the separately revalidated tenant source without fabricating human MFA',async()=>{
 const created=await create();const enabled=await update(created.client,{enabled:true});const payload={actor_type:'application',client_id:enabled.client.clientId,client_revision:enabled.client.version,company_tenant:tenant};
 assert.equal(await registry.active(payload),true);registry.companyTenantActive=async()=>false;assert.equal(await registry.active(payload),false);assert.equal(await registry.current(await registry.get(enabled.client.clientId)),false);
 assert.equal(payload.identity_authorization,undefined);assert.equal(payload.mfa_authorization,undefined);
});
test('expiration after the last successful authority check prevents the actual physical credential commit',async()=>{
 proof.validUntil=Math.floor(Date.now()/1000)+2;const actual=database.pool;database.pool={connect:async()=>{const client=await actual.connect();return{query:async(sql,...values)=>{if(sql==='COMMIT')await pool.query('SELECT pg_sleep(2.1)');return client.query(sql,...values);},release:()=>client.release()};}};
 await assert.rejects(create(),{status:503});assert.equal((await pool.query('SELECT count(*) AS n FROM oauth_clients')).rows[0].n,'0');assert.equal((await pool.query('SELECT count(*) AS n FROM oauth_company_app_outbox')).rows[0].n,'0');
});
test('a lost post-commit authority acknowledgement releases no credential and original replay recovers without creating another app',async()=>{
 let calls=0;const request=input();apps.authority=async()=>{if(++calls===3)contract.fail(401,'original_authority_withdrawn_after_commit');return contract.source(proof,user);};
 await assert.rejects(create(request),{status:401});assert.equal((await pool.query('SELECT count(*) AS n FROM oauth_clients')).rows[0].n,'1');
 apps.authority=async()=>contract.source(proof,user);const recovered=await create(request);assert.equal(recovered.created,false);assert.equal(recovered.clientSecret,null);assert.equal((await pool.query('SELECT count(*) AS n FROM oauth_client_audit')).rows[0].n,'1');
});
test('migration replay retains actual canonical credentials, original events and pending receipts',async()=>{
 const created=await create();const before=(await pool.query('SELECT * FROM oauth_clients')).rows;
 await pool.query(fs.readFileSync(path.join(__dirname,'../../migrations/014_company_app_registry.sql'),'utf8'));
 assert.deepEqual((await pool.query('SELECT * FROM oauth_clients')).rows,before);assert.equal((await apps.read(created.client.clientId,user,'Bearer original-owner')).client.version,'1');assert.equal((await apps.history(created.client.clientId,{},user,'Bearer original-owner')).events.length,1);
});
test('actual own namespace pagination and the retained catalog limit do not include foreign or deleted clients',async()=>{
 const records=[];for(let index=0;index<100;index++)records.push((await create({...input(),name:'Actual bounded app '+index})).client);
 const first=await apps.list({},user,'Bearer original-owner');assert.equal(first.clients.length,25);assert.equal(first.hasMore,true);const fourth=await apps.list({page:'4'},user,'Bearer original-owner');assert.equal(fourth.clients.length,25);assert.equal(fourth.hasMore,false);
 await assert.rejects(create(),{status:429});const retired=records[0];await apps.mutate(retired.clientId,etag(retired),{reason:'Retire one app while preserving its original evidence',confirm:true},user,'Bearer original-owner','deleted');
 const archived=await apps.list({status:'deleted'},user,'Bearer original-owner');assert.deepEqual(archived.clients.map(row=>row.clientId),[retired.clientId]);assert.equal(archived.clients[0].enabled,false);
 const created=await create();assert.equal(created.created,true);assert.equal((await pool.query('SELECT count(*) AS n FROM oauth_clients')).rows[0].n,'101');assert.equal((await apps.history(retired.clientId,{},user,'Bearer original-owner')).events.length,2);
});
