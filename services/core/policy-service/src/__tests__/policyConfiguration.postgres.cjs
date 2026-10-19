'use strict';
const { test,before,beforeEach,after }=require('node:test');
const assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const fs=require('node:fs');const path=require('node:path');const {Pool}=require('pg');
const {PolicyConfiguration,etag}=require('../PolicyConfiguration');
const schema='policy_config_'+randomUUID().replaceAll('-','');
const administration=new Pool({connectionString:process.env.LICENSE_TEST_DATABASE_URL,max:1});let pool;let store;let state;
const actorId=randomUUID();
const reviewerId=randomUUID();
function actor(roles=['policy-administrator'],userId=actorId){const authTime=Math.floor(Date.now()/1000);return{actor_type:'user',token_use:'access',iss:'https://policy-config.test',sub:'owned-config-'+userId,client_id:'owned-client',jti:randomUUID(),exp:authTime+3600,iat:authTime,roles,
 identity_authorization:{userId,revision:'1',linkRevision:'1',rolesRevision:'a'.repeat(64)},auth_time:authTime,amr:['pwd','otp'],mfa_authorization:{schemaVersion:1,userId,revision:'1',authTime,methods:['pwd','otp']}};}
const explanation={reason:'Explicit owned canonical policy configuration',acknowledgeScope:true};
const draft=(changes={})=>({name:'Owned configuration',type:'security',platform:'all',settings:{firewall:true},...explanation,...changes});
const create=(changes={})=>store.create(draft(changes),actor(),'Bearer owned.actor.proof');
const mutate=async(row,action,body={})=>{
 if(action==='activated'){
  const frame=await store.publications.get('policy',row.id,actor(),'Bearer owned.actor.proof');
  const pending=await store.publications.request('policy',row.id,etag('policy',row),{reviewerUserId:reviewerId,validitySeconds:300,configurationHash:frame.configurationHash,...explanation},actor(),'Bearer owned.actor.proof');
  const approved=await store.publications.transition('policy',row.id,pending.id,require('../PolicyPublication').publicationTag(pending),{decision:'approved',resourceVersion:row.version,configurationHash:frame.configurationHash,...explanation},actor(['policy-publication-reviewer'],reviewerId),'Bearer owned.actor.proof');
  body={...body,publicationId:approved.id};
 }
 return store.mutate(row.id,etag('policy',row),{...body,...explanation},actor(),'Bearer owned.actor.proof',action);
};
before(async()=>{
 await administration.query(`CREATE SCHEMA ${schema}`);const url=new URL(process.env.LICENSE_TEST_DATABASE_URL);url.searchParams.set('options',`-c search_path=${schema},public`);pool=new Pool({connectionString:url.toString(),max:8});
 for(const file of ['001_policies.sql','003_blueprints.sql','018_policy_configuration.sql','019_policy_publication.sql'])await pool.query(fs.readFileSync(path.join(__dirname,'../db/migrations',file),'utf8'));
});
beforeEach(async()=>{await pool.query("CREATE OR REPLACE FUNCTION policy_configuration_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp(); $$");await pool.query('TRUNCATE policy_publication_outbox,policy_publication_audit,policy_publications,policy_publication_heads,policy_configuration_outbox,policy_configuration_audit,policy_configuration_origins,policy_assignments,policy_links,policies,blueprint_assignments,blueprint_configurations,blueprints CASCADE');state={checks:0,hook:null};store=new PolicyConfiguration({getClient:()=>pool.connect(),query:(...args)=>pool.query(...args)},{authority:async()=>{state.checks++;if(state.hook)await state.hook(state.checks);},publicationSource:{actor:async()=>({enabled:true,linked:true,requestRevision:'b'.repeat(64),reviewRevision:'c'.repeat(64)})}});});
after(async()=>{if(pool)await pool.end();await administration.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);await administration.end();});
test('real policy mutations atomically derive exact versions, original actor evidence and a pending outbox without policy payload secrets',async()=>{
 const row=await create({settings:{password:'owned-policy-payload-not-an-audit-field'}});assert.equal(row.version,1);assert.equal(row.status,'draft');assert.equal(row.created_by,actorId);
 const next=await mutate(row,'activated');assert.equal(next.version,2);assert.equal(next.status,'active');
 const audit=(await pool.query('SELECT * FROM policy_configuration_audit ORDER BY version')).rows;assert.deepEqual(audit.map(item=>item.action),['created','activated']);assert.equal(audit[1].actor.userId,actorId);assert.equal(JSON.stringify(audit).includes('owned-policy-payload-not-an-audit-field'),false);assert.equal((await pool.query('SELECT count(*)::int AS count FROM policy_configuration_outbox')).rows[0].count,2);
});
test('missing and stale policy versions cannot overwrite or reactivate a different configuration',async()=>{
 const row=await create();await assert.rejects(store.mutate(row.id,undefined,explanation,actor(),'Bearer owned.actor.proof','activated'),{status:428});
 const changed=await mutate(row,'updated',{settings:{firewall:false}});assert.equal(changed.version,2);await assert.rejects(mutate(row,'activated'),{status:412});
 assert.equal((await pool.query('SELECT status FROM policies')).rows[0].status,'draft');assert.equal((await mutate(changed,'activated')).version,3);
});
test('policy children change their parent generation in the same transaction and deletion retains terminal evidence',async()=>{
 const row=await create();const linked=await store.child('policy',row.id,etag('policy',row),{targetType:'device',targetId:'owned-device',...explanation},actor(),'Bearer owned.actor.proof','assigned');assert.equal(linked.parent.version,2);
 const deleted=await mutate(linked.parent,'deleted');assert.equal(deleted.version,3);assert.equal((await pool.query('SELECT count(*)::int AS count FROM policy_assignments')).rows[0].count,0);assert.equal((await pool.query("SELECT action FROM policy_configuration_audit WHERE version=3")).rows[0].action,'deleted');
});
test('blueprint configuration and target changes share exact parent versions with no mutable memory fallback',async()=>{
 const row=await store.blueprint({name:'Owned blueprint',platform:'windows',...explanation},actor(),'Bearer owned.actor.proof');
 const config=await store.child('blueprint',row.id,etag('blueprint',row),{config_type:'wifi',config_name:'Owned wifi',payload:{ssid:'Owned'},...explanation},actor(),'Bearer owned.actor.proof','configuration_added');assert.equal(config.parent.version,2);
 const target=await store.child('blueprint',row.id,etag('blueprint',config.parent),{target_type:'device',target_id:'owned-device',...explanation},actor(),'Bearer owned.actor.proof','assigned');assert.equal(target.parent.version,3);
 await assert.rejects(store.child('blueprint',row.id,etag('blueprint',row),explanation,actor(),'Bearer owned.actor.proof','configuration_removed',undefined,config.row.id),{status:412});
 const removed=await store.child('blueprint',row.id,etag('blueprint',target.parent),explanation,actor(),'Bearer owned.actor.proof','configuration_removed',undefined,config.row.id);assert.equal(removed.parent.version,4);
 const deleted=await store.blueprint(explanation,actor(),'Bearer owned.actor.proof',undefined,row.id,etag('blueprint',removed.parent),'deleted');assert.equal(deleted.version,5);
});
test('an unavailable mandatory audit rolls back the policy, origin and outbox instead of acknowledging a saved row',async()=>{
 await pool.query('ALTER TABLE policy_configuration_audit RENAME TO owned_unavailable_audit');try{await assert.rejects(create(),{status:503});}finally{await pool.query('ALTER TABLE owned_unavailable_audit RENAME TO policy_configuration_audit');}
 for(const name of ['policies','policy_configuration_origins','policy_configuration_audit','policy_configuration_outbox'])assert.equal((await pool.query(`SELECT count(*)::int AS count FROM ${name}`)).rows[0].count,0);
});
test('original authority lost after real policy DML rolls back every derived change',async()=>{
 state.hook=async count=>{if(count===3)throw Object.assign(new Error('Owned original actor withdrawn'),{status:401});};await assert.rejects(create(),{status:401});
 assert.equal((await pool.query('SELECT count(*)::int AS count FROM policies')).rows[0].count,0);assert.equal((await pool.query('SELECT count(*)::int AS count FROM policy_configuration_audit')).rows[0].count,0);
});
test('the original operator is rechecked after the actual policy row lock, not only before waiting',async()=>{
 const row=await create();const blocker=await pool.connect();let pending;state.checks=0;let admitted=true;state.hook=async()=>{if(!admitted)throw Object.assign(new Error('Owned role expired behind lock'),{status:401});};
 try{await blocker.query('BEGIN');await blocker.query('SELECT id FROM policies WHERE id=$1 FOR UPDATE',[row.id]);pending=mutate(row,'updated',{settings:{behindLock:true}});pending.catch(()=>{});let waiting=false;
 for(let attempt=0;attempt<200;attempt++){waiting=(await pool.query("SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'SELECT * FROM policies WHERE id=%FOR UPDATE'")).rows.length>0;if(waiting)break;await new Promise(resolve=>setTimeout(resolve,10));}assert.equal(waiting,true);admitted=false;await blocker.query('COMMIT');await assert.rejects(pending,{status:401});assert.equal((await pool.query('SELECT version FROM policies')).rows[0].version,1);
 }finally{await blocker.query('ROLLBACK');blocker.release();if(pending)await pending.catch(()=>{});}
});
test('a known MFA cutoff crossed after the last issuer check is rejected by the real deferred commit guard',async()=>{
 await pool.query('CREATE TABLE owned_policy_clock(seconds integer NOT NULL);INSERT INTO owned_policy_clock VALUES(0)');await pool.query("CREATE OR REPLACE FUNCTION policy_configuration_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+seconds*interval '1 second' FROM owned_policy_clock; $$");
 state.hook=async count=>{if(count===3)await pool.query('UPDATE owned_policy_clock SET seconds=301');};
 try{await assert.rejects(create(),{status:428});assert.equal((await pool.query('SELECT count(*)::int AS count FROM policy_configuration_audit')).rows[0].count,0);}finally{await pool.query("CREATE OR REPLACE FUNCTION policy_configuration_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp(); $$;DROP TABLE owned_policy_clock");}
});
test('parallel writers using the same captured version have one actual winner and one immutable transition',async()=>{
 const row=await create();const results=await Promise.allSettled([mutate(row,'updated',{settings:{winner:'first'}}),mutate(row,'updated',{settings:{winner:'second'}})]);assert.equal(results.filter(result=>result.status==='fulfilled').length,1);assert.equal(results.find(result=>result.status==='rejected').reason.status,412);assert.equal((await pool.query('SELECT version FROM policies')).rows[0].version,2);assert.equal((await pool.query('SELECT count(*)::int AS count FROM policy_configuration_audit')).rows[0].count,2);
});
test('a duplicate assignment cannot create duplicate remote targets or advance the policy version',async()=>{
 const row=await create();const body={targetType:'device',targetId:'owned-device',...explanation};const target=await store.child('policy',row.id,etag('policy',row),body,actor(),'Bearer owned.actor.proof','assigned');
 await assert.rejects(store.child('policy',row.id,etag('policy',target.parent),body,actor(),'Bearer owned.actor.proof','assigned'),{status:409});assert.equal((await pool.query('SELECT version FROM policies')).rows[0].version,2);
});
test('raw SQL cannot edit versions, delete children or forge audit, outbox and retained origins without their original transition',async()=>{
 const row=await create();for(const sql of ["UPDATE policies SET version=99","DELETE FROM policies","DELETE FROM policy_configuration_audit","DELETE FROM policy_configuration_origins","DELETE FROM policy_configuration_outbox","INSERT INTO policy_audit_log(action) VALUES('forged')"]){await assert.rejects(pool.query(sql),error=>error.code==='42501');}
 assert.equal((await pool.query('SELECT version FROM policies WHERE id=$1',[row.id])).rows[0].version,1);
});
test('GPO and update-ring records are real canonical drafts with no default global recipients or fabricated device counts',async()=>{
 const gpo=await create({type:'gpo',settings:{configuration:{screenLock:true},platforms:['windows'],gpoType:'owned'}});const ring=await create({type:'update-ring',settings:{deferralDays:{windows:14,macos:7,linux:0}},priority:0});assert.equal(gpo.status,'draft');assert.equal(ring.priority,0);
 assert.equal((await store.snapshot('policy',gpo.id,actor(),'Bearer owned.actor.proof',undefined,'gpo')).assignments.length,0);
 await assert.rejects(store.mutate(gpo.id,etag('policy',gpo),{settings:{deferralDays:{windows:0,macos:0,linux:0}},...explanation},actor(),'Bearer owned.actor.proof','updated',undefined,'update-ring'),{status:404});
});
test('migration replay does not reset accepted versions, invent historical approvals or emit another event',async()=>{
 const row=await create();await mutate(row,'updated',{settings:{firewall:false}});const before=(await pool.query('SELECT * FROM policy_configuration_audit ORDER BY version')).rows;const origins=(await pool.query('SELECT * FROM policy_configuration_origins')).rows;
 await pool.query(fs.readFileSync(path.join(__dirname,'../db/migrations/018_policy_configuration.sql'),'utf8'));assert.deepEqual((await pool.query('SELECT * FROM policy_configuration_audit ORDER BY version')).rows,before);assert.deepEqual((await pool.query('SELECT * FROM policy_configuration_origins')).rows,origins);assert.equal((await pool.query('SELECT version FROM policies')).rows[0].version,2);
});
test('a disconnected operation cannot commit a later configuration response',async()=>{
 const row=await create();const controller=new AbortController();state.checks=0;state.hook=async count=>{if(count===3)controller.abort();};await assert.rejects(store.mutate(row.id,etag('policy',row),{settings:{firewall:false},...explanation},actor(),'Bearer owned.actor.proof','updated',controller.signal),{status:409});assert.equal((await pool.query('SELECT version FROM policies')).rows[0].version,1);
});
test('null clearing and zero priorities persist the exact acknowledged configuration rather than coalescing back to old values',async()=>{
 const row=await create({description:'Original description',wmi_filter:{conditions:[]},priority:5});const next=await mutate(row,'updated',{description:null,wmi_filter:null,priority:0});assert.equal(next.description,null);assert.equal(next.wmi_filter,null);assert.equal(next.priority,0);
});
test('a deleted policy UUID cannot be recreated even with a newly prepared creation context',async()=>{
 const row=await create();await mutate(row,'deleted');const actorProof=(await pool.query('SELECT actor FROM policy_configuration_audit ORDER BY version LIMIT 1')).rows[0].actor;const client=await pool.connect();
 try{await client.query('BEGIN');await client.query("SELECT set_config('opendirectory.policy_configuration',$1,true)",[JSON.stringify({actor:actorProof,resourceKind:'policy',resourceId:null,expectedVersion:'0',permission:'policies.manage',action:'created',...explanation})]);await assert.rejects(client.query("INSERT INTO policies(id,name,type,platform,created_by) VALUES($1,'Forbidden UUID reuse','security','all',$2)",[row.id,actorId]),error=>error.code==='23514');}
 finally{await client.query('ROLLBACK');client.release();}assert.equal((await pool.query('SELECT count(*)::int AS count FROM policies')).rows[0].count,0);assert.equal((await pool.query('SELECT count(*)::int AS count FROM policy_configuration_origins')).rows[0].count,1);
});
test('legacy adoption observes actual IDs and versions without restamping old active records or manufacturing approval evidence',async()=>{
 const legacy=schema+'_old';await administration.query(`CREATE SCHEMA ${legacy}`);const client=await pool.connect();const id=randomUUID();
 try{await client.query('BEGIN');await client.query(`SET LOCAL search_path=${legacy},public`);for(const file of ['001_policies.sql','003_blueprints.sql'])await client.query(fs.readFileSync(path.join(__dirname,'../db/migrations',file),'utf8'));
 await client.query("INSERT INTO policies(id,name,type,platform,version,status,settings,created_by) VALUES($1,'Observed legacy policy','security','all',8,'active',$2,'unverified-legacy-origin')",[id,{legacy:true}]);
 await client.query(fs.readFileSync(path.join(__dirname,'../db/migrations/018_policy_configuration.sql'),'utf8'));const observed=(await client.query('SELECT * FROM policies')).rows[0];assert.equal(observed.version,8);assert.equal(observed.status,'active');assert.equal(observed.created_by,'unverified-legacy-origin');assert.equal((await client.query('SELECT origin FROM policy_configuration_origins')).rows[0].origin,'legacy-observed');assert.equal((await client.query('SELECT count(*)::int AS count FROM policy_configuration_audit')).rows[0].count,0);
 }finally{await client.query('ROLLBACK');client.release();await administration.query(`DROP SCHEMA ${legacy} CASCADE`);}
});
test('known original token expiry between the final live check and commit cannot produce a saved policy or evidence',async()=>{
 await pool.query('CREATE TABLE owned_token_clock(seconds integer NOT NULL);INSERT INTO owned_token_clock VALUES(0)');await pool.query("CREATE OR REPLACE FUNCTION policy_configuration_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+seconds*interval '1 second' FROM owned_token_clock; $$");const user=actor();user.exp=Math.floor(Date.now()/1000)+1;state.hook=async count=>{if(count===3)await pool.query('UPDATE owned_token_clock SET seconds=2');};
 try{await assert.rejects(store.create(draft(),user,'Bearer owned.actor.proof'),{status:401});assert.equal((await pool.query('SELECT count(*)::int AS count FROM policy_configuration_outbox')).rows[0].count,0);}finally{await pool.query("CREATE OR REPLACE FUNCTION policy_configuration_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp(); $$;DROP TABLE owned_token_clock");}
});
