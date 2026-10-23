'use strict';

const {test,before,beforeEach,after}=require('node:test');
const assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const fs=require('node:fs');const path=require('node:path');
const {Pool}=require('pg');
const {DirectoryCreator}=require('../DirectoryCreator');
const {DirectoryReader}=require('../DirectoryReader');
const {AuthorizationState}=require('../AuthorizationState');
const {sameContext}=require('../../../../../packages/identity-authorization-contract');
const {provisionTenant,adoptTenant}=require('../../../../../scripts/lib/tenant-ownership-fixture.cjs');
const schema='creations_'+randomUUID().replaceAll('-','');const administration=new Pool({connectionString:process.env.IDENTITY_TEST_DATABASE_URL,max:1});
const issuer='https://creation.test';const migrations=path.join(__dirname,'../../migrations');let pool;let database;
before(async()=>{
 await administration.query('CREATE SCHEMA '+schema);pool=new Pool({connectionString:process.env.IDENTITY_TEST_DATABASE_URL,max:10,options:`-c search_path=${schema},public`});
 database={isAvailable:()=>true,query:(...args)=>pool.query(...args),getClient:()=>pool.connect(),transaction:async(operation,options={})=>{
  const client=await pool.connect();try{await client.query(options.readOnly?'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY':'BEGIN');await client.query("SET LOCAL lock_timeout='5s';SET LOCAL statement_timeout='15s'");if(options.actor)await client.query("SELECT set_config('opendirectory.actor',$1,true)",[options.actor]);const result=await operation(client);await client.query('COMMIT');return result;}catch(error){await client.query('ROLLBACK');throw error;}finally{client.release();}
 }};
 for(const file of fs.readdirSync(migrations).filter(file=>file.endsWith('.sql')).sort())await pool.query(fs.readFileSync(path.join(migrations,file),'utf8'));
});
beforeEach(async()=>{await pool.query('TRUNCATE identity_tenants,users,groups,ous,identity_deleted_users,identity_deleted_groups,identity_user_audit,identity_user_outbox,identity_authorization_audit,identity_group_audit,identity_group_outbox CASCADE');});
after(async()=>{await pool.end();await administration.query('DROP SCHEMA '+schema+' CASCADE');await administration.end();});
async function actor(role='admin'){
 const tenant=await provisionTenant(database,schema,{enabled:true});const userId=randomUUID();const subject='creator-'+randomUUID();
 await pool.query('INSERT INTO users(id,username,email) VALUES($1,$2,$3)',[userId,subject,subject+'@test.invalid']);await pool.query('INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES($1,$2,$3)',[issuer,subject,userId]);
 await adoptTenant(database,schema,tenant,[{kind:'user',resourceId:userId}]);await pool.query('INSERT INTO identity_role_assignments(user_id,role,reason) VALUES($1,$2,$3)',[userId,role,'Explicit owned canonical resource creator']);
 const state=await new AuthorizationState(database).state(issuer,subject);const user={iss:issuer,sub:subject,actor_type:'user',roles:state.roles,identity_authorization:state.context,exp:Math.floor(Date.now()/1000)+300};
 const live={checks:0,revoked:false,onCheck:null};const revalidate=async(_authorization,original)=>{
  live.checks++;if(live.onCheck)await live.onCheck(live.checks);const current=await new AuthorizationState(database).state(issuer,original.sub);
  if(live.revoked||!current.active||!sameContext(current.context,original.identity_authorization))throw Object.assign(new Error('Original owned creator revoked'),{status:401});return current.tenant;
 };
 return{tenant,user,live,revalidate,creator:new DirectoryCreator(database,{issuer,revalidate}),reader:new DirectoryReader(database,{issuer,revalidate})};
}
const body=kind=>kind==='user'?{username:'new-'+randomUUID(),email:randomUUID()+'@test.invalid'}:{name:'New owned '+kind};
const table=kind=>({user:'users',group:'groups',ou:'ous'})[kind];
const owner=async(kind,identity)=>(await pool.query('SELECT identity_tenant_id($1,$2) AS owner',[kind,identity])).rows[0].owner;
async function absent(kind,identity){assert.equal((await pool.query('SELECT count(*)::int AS count FROM '+table(kind)+' WHERE id=$1',[identity])).rows[0].count,0);assert.equal(await owner(kind,identity),null);assert.equal((await pool.query("SELECT count(*)::int AS count FROM identity_tenant_events WHERE details->>'resourceId'=$1",[identity])).rows[0].count,0);}
function wrapped(operation){return{...database,transaction:(callback,options)=>database.transaction(async client=>{const result=await callback(client);await operation(client,result);return result;},options)};}

test('production creation owns a disabled canonical user atomically without any fixture adoption hook or credential provisioning',async()=>{
 const first=await actor();const second=await actor();const profile={...body('user'),displayName:'Owned created person'};const created=await first.creator.user(profile,first.user,'Bearer original');
 assert.equal(created.enabled,false);assert.equal(await owner('user',created.id),first.tenant);assert.deepEqual(await first.reader.user(created.id,{},first.user,'Bearer original'),created);await assert.rejects(second.reader.user(created.id,{},second.user,'Bearer original'),error=>error.status===404);
 const stored=(await pool.query('SELECT record_revision,tenant_generation,identity_tenant_user_enabled(id) AS enabled FROM users WHERE id=$1',[created.id])).rows[0];assert.equal(String(stored.record_revision),created.revision);assert.ok(BigInt(stored.tenant_generation)>0n);assert.equal(stored.enabled,false);
 for(const source of['identity_subject_links','identity_role_assignments'])assert.equal((await pool.query('SELECT count(*)::int AS count FROM '+source+' WHERE user_id=$1',[created.id])).rows[0].count,0);
 const evidence=(await pool.query("SELECT event.actor,event.details,outbox.action FROM identity_tenant_events event JOIN identity_tenant_outbox outbox USING(id) WHERE event.action='resource-created' AND event.details->>'resourceId'=$1",[created.id])).rows;
 assert.equal(evidence.length,1);assert.equal(evidence[0].actor.userId,first.user.identity_authorization.userId);assert.equal(evidence[0].details.origin,'original-token-directory-creation');assert.match(evidence[0].details.contentSha256,/^[a-f0-9]{64}$/);assert.equal(JSON.stringify(evidence).includes('Bearer'),false);assert.equal(JSON.stringify(evidence).includes(profile.email),false);
});
test('new groups and OU trees derive the actual creator tenant rather than a default owner or supplied group members',async()=>{
 const first=await actor();const second=await actor();const group=await second.creator.group(body('group'),second.user,'Bearer original');const root=await second.creator.ou(body('ou'),second.user,'Bearer original');const child=await second.creator.ou({...body('ou'),parentId:root.id.toUpperCase()},second.user,'Bearer original');
 assert.deepEqual(group.members,[]);assert.equal((await pool.query('SELECT count(*)::int AS count FROM group_members WHERE group_id=$1',[group.id])).rows[0].count,0);for(const[kind,identity]of[['group',group.id],['ou',root.id],['ou',child.id]])assert.equal(await owner(kind,identity),second.tenant);
 assert.equal(child.parentId,root.id);assert.equal((await second.reader.ous({},second.user,'Bearer original')).tree[0].children[0].id,child.id);await assert.rejects(first.reader.group(group.id,{},first.user,'Bearer original'),error=>error.status===404);
});
test('foreign and missing OU parents are rejected before a new namespace is acknowledged',async()=>{
 const first=await actor();const second=await actor();const parent=await second.creator.ou(body('ou'),second.user,'Bearer original');
 for(const parentId of[parent.id,randomUUID()]){const identity=randomUUID();const creator=new DirectoryCreator(database,{issuer,revalidate:first.revalidate,newResourceId:()=>identity});await assert.rejects(creator.ou({...body('ou'),parentId},first.user,'Bearer original'),error=>error.status===404);await absent('ou',identity);}
});
test('caller-selected owners, UUIDs, enablement, roles, members and unsupported OU fields cannot widen creation',async()=>{
 const fixture=await actor();for(const[kind,changes]of[['user',[{tenantId:fixture.tenant},{id:randomUUID()},{enabled:true},{roles:['admin']},{password:'not-provisioned'}]],['group',[{tenantId:fixture.tenant},{members:[randomUUID()]},{parentId:randomUUID()}]],['ou',[{tenantId:fixture.tenant},{parentId:'legacy'},{owner:fixture.tenant}]]]){
  for(const change of changes)await assert.rejects(fixture.creator[kind]({...body(kind),...change},fixture.user,'Bearer original'),error=>error.status===400);
 }assert.equal(fixture.live.checks,0);
});
test('ordinary readers, workloads and unbound legacy principals cannot borrow an enabled owner to create resources',async()=>{
 const fixture=await actor('directory-reader');for(const user of[fixture.user,{...fixture.user,roles:['admin'],actor_type:'application'},{...fixture.user,roles:['admin'],identity_authorization:undefined},{...fixture.user,roles:['admin'],iss:'https://foreign.test'}])await assert.rejects(fixture.creator.user(body('user'),user,'Bearer original'),error=>error.status===403);assert.equal(fixture.live.checks,0);
});
test('revocation after actual creation DML rolls back row, owner, all user evidence and the creation outbox',async()=>{
 const fixture=await actor();const identity=randomUUID();fixture.live.onCheck=async number=>{if(number===3)fixture.live.revoked=true;};const creator=new DirectoryCreator(database,{issuer,revalidate:fixture.revalidate,newResourceId:()=>identity});
 await assert.rejects(creator.user(body('user'),fixture.user,'Bearer original'),error=>error.status===401);await absent('user',identity);for(const source of['identity_user_audit','identity_user_outbox','identity_user_record_audit'])assert.equal((await pool.query('SELECT count(*)::int AS count FROM '+source+' WHERE user_id=$1',[identity])).rows[0].count,0);
});
test('missing mandatory owner/user audit or outbox rolls back the real new namespace rather than fabricating creation',async()=>{
 const fixture=await actor();for(const source of['identity_tenant_events','identity_tenant_outbox','identity_user_audit','identity_user_outbox']){const identity=randomUUID();const creator=new DirectoryCreator(database,{issuer,revalidate:fixture.revalidate,newResourceId:()=>identity});await pool.query('ALTER TABLE '+source+' RENAME TO withheld_creation_evidence');
  try{await assert.rejects(creator.user(body('user'),fixture.user,'Bearer original'));}finally{await pool.query('ALTER TABLE withheld_creation_evidence RENAME TO '+source);}await absent('user',identity);
 }
});
test('original revocation during an observed OU parent lock wait stops creation after the lock is released',async()=>{
 const fixture=await actor();const parent=await fixture.creator.ou(body('ou'),fixture.user,'Bearer original');fixture.live.checks=0;const identity=randomUUID();const creator=new DirectoryCreator(database,{issuer,revalidate:fixture.revalidate,newResourceId:()=>identity});const blocker=await pool.connect();let pending;
 try{await blocker.query('BEGIN');await blocker.query('SELECT id FROM ous WHERE id=$1 FOR UPDATE',[parent.id]);pending=creator.ou({...body('ou'),parentId:parent.id},fixture.user,'Bearer original');pending.catch(()=>{});let waiting=false;
  for(let attempt=0;attempt<200;attempt++){waiting=(await pool.query("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'SELECT id FROM ous WHERE id=%FOR KEY SHARE') AS waiting")).rows[0].waiting;if(waiting)break;await new Promise(resolve=>setTimeout(resolve,5));}assert.equal(waiting,true);fixture.live.revoked=true;await blocker.query('COMMIT');await assert.rejects(pending,error=>error.status===401);await absent('ou',identity);
 }finally{await blocker.query('ROLLBACK');blocker.release();if(pending)await pending.catch(()=>{});}
});
test('an observed new-namespace advisory wait cannot preserve original authority revoked during SQL',async()=>{
 const fixture=await actor();const identity=randomUUID();const creator=new DirectoryCreator(database,{issuer,revalidate:fixture.revalidate,newResourceId:()=>identity});const blocker=await pool.connect();let pending;
 try{await blocker.query('BEGIN');await blocker.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',['identity-tenant-resource:user:'+identity]);pending=creator.user(body('user'),fixture.user,'Bearer original');pending.catch(()=>{});let waiting=false;
  for(let attempt=0;attempt<200;attempt++){waiting=(await pool.query("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event='advisory' AND query LIKE 'INSERT INTO users(id,username,email,display_name,%') AS waiting")).rows[0].waiting;if(waiting)break;await new Promise(resolve=>setTimeout(resolve,5));}assert.equal(waiting,true);fixture.live.revoked=true;await blocker.query('COMMIT');await assert.rejects(pending,error=>error.status===401);await absent('user',identity);
 }finally{await blocker.query('ROLLBACK');blocker.release();if(pending)await pending.catch(()=>{});}
});
test('deferred creation admission rejects canonical role loss after the last original-token checkpoint',async()=>{
 const fixture=await actor();const identity=randomUUID();const changed=wrapped(client=>client.query('UPDATE identity_role_assignments SET revoked_at=clock_timestamp() WHERE user_id=$1',[fixture.user.identity_authorization.userId]));
 await assert.rejects(new DirectoryCreator(changed,{issuer,revalidate:fixture.revalidate,newResourceId:()=>identity}).user(body('user'),fixture.user,'Bearer original'),error=>error.code==='42501');await absent('user',identity);assert.equal((await new AuthorizationState(database).state(issuer,fixture.user.sub)).roles.includes('admin'),true);
});
test('deferred creation admission enforces physical token expiry even after a positive final checkpoint',async()=>{
 const fixture=await actor();fixture.user.exp=Math.floor(Date.now()/1000)+2;const identity=randomUUID();const delayed=wrapped(client=>client.query('SELECT pg_sleep(2.1)'));
 await assert.rejects(new DirectoryCreator(delayed,{issuer,revalidate:fixture.revalidate,newResourceId:()=>identity}).user(body('user'),fixture.user,'Bearer original'),error=>error.code==='42501');await absent('user',identity);
});
for(const kind of['user','group','ou'])test('deferred '+kind+' creation content cannot drift after SQL or activate a disabled-first user',async()=>{
 const fixture=await actor();const identity=randomUUID();const changed=wrapped(client=>client.query(kind==='user'?'UPDATE users SET enabled=true,title=$2 WHERE id=$1':'UPDATE '+table(kind)+' SET name=$2 WHERE id=$1',[identity,'Unconfirmed post-checkpoint content']));
 await assert.rejects(new DirectoryCreator(changed,{issuer,revalidate:fixture.revalidate,newResourceId:()=>identity})[kind](body(kind),fixture.user,'Bearer original'),error=>error.code==='23514');await absent(kind,identity);
});
for(const kind of['user','group','ou'])test('runtime '+kind+' creation cannot adopt a pre-existing row or resurrect its retired owned UUID',async()=>{
 const fixture=await actor();const unowned=randomUUID();await pool.query(kind==='user'?'INSERT INTO users(id,username,email) VALUES($1,$2,$3)':'INSERT INTO '+table(kind)+'(id,name) VALUES($1,$2)',kind==='user'?[unowned,'unowned-'+unowned,unowned+'@test.invalid']:[unowned,'Unowned old resource']);
 await assert.rejects(new DirectoryCreator(database,{issuer,revalidate:fixture.revalidate,newResourceId:()=>unowned})[kind](body(kind),fixture.user,'Bearer original'),error=>error.code==='23514');assert.equal(await owner(kind,unowned),null);
 const created=await fixture.creator[kind](body(kind),fixture.user,'Bearer original');await pool.query('DELETE FROM '+table(kind)+' WHERE id=$1',[created.id]);const prior=await owner(kind,created.id);
 await assert.rejects(new DirectoryCreator(database,{issuer,revalidate:fixture.revalidate,newResourceId:()=>created.id})[kind](body(kind),fixture.user,'Bearer original'),error=>error.code==='23514');assert.equal(await owner(kind,created.id),prior);
});
test('migration replay preserves actual owners, generations and creation evidence without restamping',async()=>{
 const fixture=await actor();await fixture.creator.user(body('user'),fixture.user,'Bearer original');const before=(await pool.query('SELECT * FROM identity_tenant_ownership ORDER BY resource_id')).rows;const events=(await pool.query('SELECT * FROM identity_tenant_events ORDER BY id')).rows;
 await pool.query(fs.readFileSync(path.join(migrations,'026_directory_creation.sql'),'utf8'));for(const file of ['051_company_group_rule_automation.sql','052_live_company_group_rules.sql','053_company_automation_changes.sql','054_company_app_automation_tenants.sql','055_employee_enrollments.sql'])await pool.query(fs.readFileSync(path.join(migrations,file),'utf8'));await pool.query('SELECT identity_company_group_rule_live_receiving()');assert.deepEqual((await pool.query('SELECT * FROM identity_tenant_ownership ORDER BY resource_id')).rows,before);assert.deepEqual((await pool.query('SELECT * FROM identity_tenant_events ORDER BY id')).rows,events);await fixture.creator.group(body('group'),fixture.user,'Bearer original');
});
test('creation context does not leak across pooled transactions or turn later raw SQL into runtime adoption',async()=>{
 const fixture=await actor();const client=await pool.connect();const identity=randomUUID();
 try{
  const fixed={...database,transaction:async(operation,options={})=>{try{await client.query('BEGIN');if(options.actor)await client.query("SELECT set_config('opendirectory.actor',$1,true)",[options.actor]);const result=await operation(client);await client.query('COMMIT');return result;}catch(error){await client.query('ROLLBACK');throw error;}}};
  await new DirectoryCreator(fixed,{issuer,revalidate:fixture.revalidate}).user(body('user'),fixture.user,'Bearer original');await client.query('INSERT INTO users(id,username,email) VALUES($1,$2,$3)',[identity,'later-'+identity,identity+'@test.invalid']);assert.equal(await owner('user',identity),null);
 }finally{await client.query('ROLLBACK');client.release();}
});
test('a missing creation receiver trigger cannot be disguised as a confirmed owned creation',async()=>{
 const fixture=await actor();const identity=randomUUID();await pool.query('ALTER TABLE users DISABLE TRIGGER aaa_identity_directory_creation;ALTER TABLE users DISABLE TRIGGER identity_directory_creation_commit');
 try{await assert.rejects(new DirectoryCreator(database,{issuer,revalidate:fixture.revalidate,newResourceId:()=>identity}).user(body('user'),fixture.user,'Bearer original'),error=>error.status===503&&error.message==='Tenant-bound creation receipt unavailable');}
 finally{await pool.query('ALTER TABLE users ENABLE TRIGGER aaa_identity_directory_creation;ALTER TABLE users ENABLE TRIGGER identity_directory_creation_commit');}await absent('user',identity);
});
async function captureProof(fixture,identity,profile){
 let proof;const capture={...database,transaction:(callback,options)=>database.transaction(client=>callback({query:async(sql,values)=>{if(sql.startsWith("SELECT set_config('opendirectory.directory_creation'")){proof=JSON.parse(values[0]);throw new Error('Explicit proof capture without a resource');}return client.query(sql,values);}}),options)};
 await assert.rejects(new DirectoryCreator(capture,{issuer,revalidate:fixture.revalidate,newResourceId:()=>identity}).user(profile,fixture.user,'Bearer original'),/Explicit proof capture/);return proof;
}
test('a creation proof alone cannot adopt an old resource or replace explicit actual-owner offline review',async()=>{
 const fixture=await actor();const identity=randomUUID();const profile=body('user');await pool.query('INSERT INTO users(id,username,email) VALUES($1,$2,$3)',[identity,profile.username,profile.email]);const proof=await captureProof(fixture,identity,profile);
 await assert.rejects(database.transaction(async client=>{await client.query("SELECT set_config('opendirectory.directory_creation',$1,true),set_config('opendirectory.directory_creation_claim',$2,true)",[JSON.stringify(proof),'user:'+identity]);await client.query("INSERT INTO identity_tenant_ownership(resource_kind,resource_id,tenant_id,reviewed_version,reason) VALUES('user',$1,$2,$3,'Original-token-bound new-resource creation')",[identity,fixture.tenant,proof.tenant.version]);}),error=>error.code==='42501'&&error.message==='Explicit actual-owner tenant review required');assert.equal(await owner('user',identity),null);
 await adoptTenant(database,schema,fixture.tenant,[{kind:'user',resourceId:identity}]);assert.equal(await owner('user',identity),fixture.tenant);
});
test('an actual limited SQL login or assumed role cannot launder a complete valid runtime creation proof through definer triggers',async()=>{
 const fixture=await actor();const identity=randomUUID();const profile=body('user');const proof=await captureProof(fixture,identity,profile);const role='creation_limited_'+randomUUID().replaceAll('-','');const password='owned-'+randomUUID();let limited;
 await administration.query(`CREATE ROLE ${role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '${password}'`);
 try{
  await pool.query(`GRANT USAGE ON SCHEMA ${schema} TO ${role};GRANT INSERT ON users TO ${role};GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA ${schema} TO ${role}`);const address=new URL(process.env.IDENTITY_TEST_DATABASE_URL);address.username=role;address.password=password;limited=new Pool({connectionString:address.toString(),max:1,options:`-c search_path=${schema},public`});
  for(const assumed of[false,true]){const client=await(assumed?pool:limited).connect();try{await client.query('BEGIN');if(assumed)await client.query('SET LOCAL ROLE '+role);await client.query("SELECT set_config('opendirectory.directory_creation',$1,true)",[JSON.stringify(proof)]);
   await assert.rejects(client.query('INSERT INTO users(id,username,email,display_name,department,title,enabled) VALUES($1,$2,$3,null,null,null,false)',[identity,profile.username,profile.email]),error=>error.code==='42501'&&error.message==='Actual database owner required for original-actor creation');
  }finally{await client.query('ROLLBACK');client.release();}}
  await absent('user',identity);
 }finally{await limited?.end();await pool.query('DROP OWNED BY '+role);await administration.query('DROP ROLE '+role);}
});
