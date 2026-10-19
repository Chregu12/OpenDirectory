'use strict';

const {test,before,beforeEach,after}=require('node:test');
const assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const fs=require('node:fs');const path=require('node:path');
const {Pool}=require('pg');
const {AuthorizationState}=require('../AuthorizationState');
const {UserSnapshotStore}=require('../UserSnapshotStore');
const {GroupSnapshotStore}=require('../GroupSnapshotStore');
const {SubjectLinks}=require('../SubjectLinks');
const {DirectoryReader}=require('../DirectoryReader');
const {sameContext}=require('../../../../../packages/identity-authorization-contract');
const {provisionTenant,enableTenant,adoptTenant,tenantScript}=require('../../../../../scripts/lib/tenant-ownership-fixture.cjs');
const schema='tenants_'+randomUUID().replaceAll('-','');const admin=new Pool({connectionString:process.env.IDENTITY_TEST_DATABASE_URL,max:1});
const issuer='https://owned-tenant.test';let pool;let database;
const migrations=path.join(__dirname,'../../migrations');
before(async()=>{
 await admin.query('CREATE SCHEMA '+schema);pool=new Pool({connectionString:process.env.IDENTITY_TEST_DATABASE_URL,max:10,options:`-c search_path=${schema},public`});
 database={isAvailable:()=>true,query:(...args)=>pool.query(...args),getClient:()=>pool.connect(),transaction:async(operation,options={})=>{const client=await pool.connect();try{await client.query(options.readOnly?'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY':'BEGIN');await client.query("SET LOCAL lock_timeout='5s';SET LOCAL statement_timeout='15s'");const result=await operation(client);await client.query('COMMIT');return result;}catch(error){await client.query('ROLLBACK');throw error;}finally{client.release();}}};
 for(const file of fs.readdirSync(migrations).filter(file=>file.endsWith('.sql')).sort())await pool.query(fs.readFileSync(path.join(migrations,file),'utf8'));
});
beforeEach(async()=>{await pool.query('TRUNCATE identity_tenants,users,groups,ous,identity_deleted_users,identity_deleted_groups,identity_user_audit,identity_user_outbox,identity_authorization_audit,identity_group_audit,identity_group_outbox CASCADE');});
after(async()=>{await pool.end();await admin.query('DROP SCHEMA '+schema+' CASCADE');await admin.end();});
async function user(){const id=randomUUID();await pool.query('INSERT INTO users(id,username,email) VALUES($1,$2,$3)',[id,'owned-'+id,id+'@test.invalid']);await pool.query('INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES($1,$2,$3)',[issuer,id,id]);return id;}
async function group(){const id=randomUUID();await pool.query('INSERT INTO groups(id,name) VALUES($1,$2)',[id,'Owned group']);return id;}
async function ou(){const id=randomUUID();await pool.query('INSERT INTO ous(id,name) VALUES($1,$2)',[id,'Owned OU']);return id;}
async function linkFixture(){
 const actor=await owned();await pool.query("INSERT INTO identity_role_assignments(user_id,role,reason) VALUES($1,'admin','Explicit owned link administrator fixture')",[actor.identity]);
 const initial=await state(actor.identity);const user={iss:issuer,sub:actor.identity,actor_type:'user',roles:initial.roles,identity_authorization:initial.context,exp:Math.floor(Date.now()/1000)+300};
 const target=await userTarget(actor.tenant);const body={issuer,subject:'new-'+randomUUID(),userId:target};const live={checks:0,revoked:false,onCheck:null};
 const revalidate=async(_authorization,original)=>{live.checks++;if(live.onCheck)await live.onCheck(live.checks);const current=await state(original.sub);if(live.revoked||!current.active||!sameContext(current.context,original.identity_authorization))throw Object.assign(new Error('Original fixture token revoked'),{status:401});return current.tenant;};
 const store=new SubjectLinks(database,{issuer,revalidate});return{actor,user,target,body,live,revalidate,store};
}
async function userTarget(tenant){const identity=await user();await adoptTenant(database,schema,tenant,[{kind:'user',resourceId:identity}]);await pool.query('DELETE FROM identity_subject_links WHERE issuer=$1 AND subject=$2',[issuer,identity]);return identity;}

test('subject-link writes derive the actual actor tenant and retain exact original actor audit and pending outbox evidence',async()=>{
 const fixture=await linkFixture();const result=await fixture.store.mutate(fixture.body,fixture.user,'Bearer original-fixture-token');assert.equal(result.user_id,fixture.target);assert.equal(fixture.live.checks,3);
 assert.equal((await pool.query('SELECT tenant_id FROM identity_subject_tenant_bindings WHERE subject=$1',[fixture.body.subject])).rows[0].tenant_id,fixture.actor.tenant);
 const evidence=(await pool.query("SELECT event.actor,event.details,outbox.action FROM identity_tenant_events event JOIN identity_tenant_outbox outbox USING(id) WHERE event.action='subject-linked' AND event.details->>'subject'=$1",[fixture.body.subject])).rows;
 assert.equal(evidence.length,1);assert.equal(evidence[0].actor.userId,fixture.actor.identity);assert.equal(evidence[0].details.userId,fixture.target);assert.equal(JSON.stringify(evidence).includes('Bearer'),false);
 await fixture.store.mutate({issuer,subject:fixture.body.subject},fixture.user,'Bearer original-fixture-token',true);assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_subject_tenant_bindings WHERE subject=$1',[fixture.body.subject])).rows[0].count,1);
});
test('a globally privileged link operator cannot create or remove another explicitly owned tenant binding',async()=>{
 const fixture=await linkFixture();const foreign=await owned();await assert.rejects(fixture.store.mutate({...fixture.body,userId:foreign.identity},fixture.user,'Bearer original'),error=>error.status===404);
 await assert.rejects(fixture.store.mutate({issuer,subject:foreign.identity},fixture.user,'Bearer original',true),error=>error.status===404);assert.equal((await state(foreign.identity)).active,true);
 const unowned=await user();await assert.rejects(fixture.store.mutate({...fixture.body,userId:unowned},fixture.user,'Bearer original'),error=>error.status===404);
});
test('deleted subjects cannot migrate to a foreign tenant or an unowned user even through raw SQL',async()=>{
 const fixture=await linkFixture();await fixture.store.mutate(fixture.body,fixture.user,'Bearer original');await pool.query('DELETE FROM users WHERE id=$1',[fixture.target]);const foreign=await owned();const unowned=await user();
 for(const target of[foreign.identity,unowned])await assert.rejects(pool.query('INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES($1,$2,$3)',[issuer,fixture.body.subject,target]),error=>error.code==='23514');
 const replacement=await userTarget(fixture.actor.tenant);assert.equal((await fixture.store.mutate({...fixture.body,userId:replacement},fixture.user,'Bearer original')).user_id,replacement);
});
test('retained subject ownership cannot be forged, updated or erased and migration replay preserves its timestamp',async()=>{
 const fixture=await linkFixture();await fixture.store.mutate(fixture.body,fixture.user,'Bearer original');const before=(await pool.query('SELECT * FROM identity_subject_tenant_bindings ORDER BY subject')).rows;
 await assert.rejects(pool.query('UPDATE identity_subject_tenant_bindings SET tenant_id=$1',[randomUUID()]),error=>error.code==='42501');await assert.rejects(pool.query('DELETE FROM identity_subject_tenant_bindings'),error=>error.code==='42501');
 await assert.rejects(pool.query('INSERT INTO identity_subject_tenant_bindings(issuer,subject,tenant_id) VALUES($1,$2,$3)',[issuer,'forged',fixture.actor.tenant]),error=>error.code==='23514');
 await pool.query(fs.readFileSync(path.join(migrations,'025_subject_tenant_bindings.sql'),'utf8'));assert.deepEqual((await pool.query('SELECT * FROM identity_subject_tenant_bindings ORDER BY subject')).rows,before);
});
test('tenant adoption claims existing known subjects atomically rather than leaving a cross-tenant relinking gap',async()=>{
 const identity=await user();const tenant=await provisionTenant(database,schema,{enabled:true});await adoptTenant(database,schema,tenant,[{kind:'user',resourceId:identity}]);assert.equal((await pool.query('SELECT tenant_id FROM identity_subject_tenant_bindings WHERE subject=$1',[identity])).rows[0].tenant_id,tenant);
 await pool.query('DELETE FROM identity_subject_links WHERE subject=$1',[identity]);const foreign=await owned();await assert.rejects(pool.query('INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES($1,$2,$3)',[issuer,identity,foreign.identity]),error=>error.code==='23514');
});
test('extra tenant selectors, guessed principals, workload claims and self-unlink have no administrator bypass',async()=>{
 const fixture=await linkFixture();for(const change of[{tenantId:fixture.actor.tenant},{approved:true},{subject:'bad\nsubject'}])await assert.rejects(fixture.store.mutate({...fixture.body,...change},fixture.user,'Bearer original'),error=>error.status===400);
 for(const user of[{...fixture.user,actor_type:'application'},{...fixture.user,identity_authorization:undefined},{...fixture.user,roles:['user']}])await assert.rejects(fixture.store.mutate(fixture.body,user,'Bearer original'),error=>error.status===403);
 await assert.rejects(fixture.store.mutate({issuer,subject:fixture.user.sub},fixture.user,'Bearer original',true),error=>error.status===403);
});
test('revocation discovered after link DML rolls back the link, retained namespace, audit and outbox together',async()=>{
 const fixture=await linkFixture();fixture.live.onCheck=async number=>{if(number===3)fixture.live.revoked=true;};const before=await count('identity_tenant_events');
 await assert.rejects(fixture.store.mutate(fixture.body,fixture.user,'Bearer original'),error=>error.status===401);assert.equal(await count('identity_tenant_events'),before);
 for(const table of['identity_subject_links','identity_subject_tenant_bindings'])assert.equal((await pool.query('SELECT count(*)::int AS count FROM '+table+' WHERE subject=$1',[fixture.body.subject])).rows[0].count,0);
 assert.equal((await pool.query("SELECT count(*)::int AS count FROM identity_link_audit WHERE details->>'subject'=$1",[fixture.body.subject])).rows[0].count,0);
});
test('a target lock wait cannot preserve previously admitted but subsequently revoked original authority',async()=>{
 const fixture=await linkFixture();const blocker=await pool.connect();let pending;
 try{await blocker.query('BEGIN');await blocker.query('SELECT id FROM users WHERE id=$1 FOR UPDATE',[fixture.target]);pending=fixture.store.mutate(fixture.body,fixture.user,'Bearer original');pending.catch(()=>{});let waiting=false;
  for(let attempt=0;attempt<200;attempt++){waiting=(await pool.query("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'SELECT id AS user_id FROM users%') AS waiting")).rows[0].waiting;if(waiting)break;await new Promise(resolve=>setTimeout(resolve,10));}assert.equal(waiting,true);
  fixture.live.revoked=true;await blocker.query('COMMIT');await assert.rejects(pending,error=>error.status===401);assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_subject_links WHERE subject=$1',[fixture.body.subject])).rows[0].count,0);
 }finally{await blocker.query('ROLLBACK');blocker.release();if(pending)await pending.catch(()=>{});}
});
test('deferred link admission detects canonical role loss after the final application checkpoint',async()=>{
 const fixture=await linkFixture();const wrapped={transaction:(operation,options)=>database.transaction(async client=>{const result=await operation(client);await client.query('UPDATE identity_role_assignments SET revoked_at=clock_timestamp() WHERE user_id=$1',[fixture.actor.identity]);return result;},options)};
 const store=new SubjectLinks(wrapped,{issuer,revalidate:fixture.revalidate});await assert.rejects(store.mutate(fixture.body,fixture.user,'Bearer original'),error=>error.code==='42501');assert.equal((await state(fixture.actor.identity)).roles.includes('admin'),true);
 assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_subject_links WHERE subject=$1',[fixture.body.subject])).rows[0].count,0);
});
test('deferred link admission enforces the physical original token deadline rather than a cached positive response',async()=>{
 const fixture=await linkFixture();fixture.user.exp=Math.floor(Date.now()/1000)+2;const wrapped={transaction:(operation,options)=>database.transaction(async client=>{const result=await operation(client);await client.query('SELECT pg_sleep(2.1)');return result;},options)};
 await assert.rejects(new SubjectLinks(wrapped,{issuer,revalidate:fixture.revalidate}).mutate(fixture.body,fixture.user,'Bearer original'),error=>error.code==='42501');
});
test('concurrent first claims cannot turn subject unlinking into a second tenant namespace',async()=>{
 const first=await linkFixture();const second=await linkFixture();const subject='concurrent-'+randomUUID();const outcomes=await Promise.allSettled([first,second].map(fixture=>fixture.store.mutate({...fixture.body,subject},fixture.user,'Bearer original')));
 assert.equal(outcomes.filter(result=>result.status==='fulfilled').length,1);const winner=outcomes[0].status==='fulfilled'?first:second;const loser=winner===first?second:first;
 await winner.store.mutate({issuer,subject},winner.user,'Bearer original',true);await assert.rejects(loser.store.mutate({...loser.body,subject},loser.user,'Bearer original'),error=>error.code==='23514');
 assert.equal((await pool.query('SELECT tenant_id FROM identity_subject_tenant_bindings WHERE subject=$1',[subject])).rows[0].tenant_id,winner.actor.tenant);
});
test('explicit adoption rejects a privileged historical unowned link that conflicts with a retained tenant',async()=>{
 const fixture=await linkFixture();await fixture.store.mutate(fixture.body,fixture.user,'Bearer original');await fixture.store.mutate({issuer,subject:fixture.body.subject},fixture.user,'Bearer original',true);
 const identity=await user();await pool.query('DELETE FROM identity_subject_links WHERE subject=$1',[identity]);await pool.query('ALTER TABLE identity_subject_links DISABLE TRIGGER identity_subject_tenant_guard;ALTER TABLE identity_subject_links DISABLE TRIGGER identity_subject_tenant_changed');
 try{await pool.query('INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES($1,$2,$3)',[issuer,fixture.body.subject,identity]);}finally{await pool.query('ALTER TABLE identity_subject_links ENABLE TRIGGER identity_subject_tenant_guard;ALTER TABLE identity_subject_links ENABLE TRIGGER identity_subject_tenant_changed');}
 const foreign=await provisionTenant(database,schema,{enabled:true});await assert.rejects(adoptTenant(database,schema,foreign,[{kind:'user',resourceId:identity}]),error=>error.code==='23514');assert.equal((await state(identity)).active,false);
});
test('missing mandatory tenant event or outbox evidence cannot acknowledge a successful link transition',async()=>{
 for(const table of['identity_tenant_events','identity_tenant_outbox']){const fixture=await linkFixture();await pool.query('ALTER TABLE '+table+' RENAME TO withheld_link_evidence');
  try{await assert.rejects(fixture.store.mutate(fixture.body,fixture.user,'Bearer original'));}finally{await pool.query('ALTER TABLE withheld_link_evidence RENAME TO '+table);}assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_subject_links WHERE subject=$1',[fixture.body.subject])).rows[0].count,0);
 }
});
test('a privileged historical cross-tenant link import cannot become positive canonical sign-in or tenant authority',async()=>{
 const fixture=await linkFixture();await fixture.store.mutate(fixture.body,fixture.user,'Bearer original');await fixture.store.mutate({issuer,subject:fixture.body.subject},fixture.user,'Bearer original',true);
 const foreign=await owned();await pool.query('DELETE FROM identity_subject_links WHERE subject=$1',[foreign.identity]);await pool.query('ALTER TABLE identity_subject_links DISABLE TRIGGER identity_subject_tenant_guard;ALTER TABLE identity_subject_links DISABLE TRIGGER identity_subject_tenant_changed');
 try{await pool.query('INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES($1,$2,$3)',[issuer,fixture.body.subject,foreign.identity]);}finally{await pool.query('ALTER TABLE identity_subject_links ENABLE TRIGGER identity_subject_tenant_guard;ALTER TABLE identity_subject_links ENABLE TRIGGER identity_subject_tenant_changed');}
 assert.deepEqual(await new AuthorizationState(database).state(issuer,fixture.body.subject),{schemaVersion:1,issuer,subject:fixture.body.subject,active:false});
});
const manifest=(kind,...identities)=>identities.map(resourceId=>({kind,resourceId}));
async function directoryFixture(){
 const fixture=await linkFixture();const foreign=await owned();const ownGroup=await group();const foreignGroup=await group();const ownOu=await ou();const foreignOu=await ou();
 await adoptTenant(database,schema,fixture.actor.tenant,[...manifest('group',ownGroup),...manifest('ou',ownOu)]);await adoptTenant(database,schema,foreign.tenant,[...manifest('group',foreignGroup),...manifest('ou',foreignOu)]);
 return{...fixture,foreign,ownGroup,foreignGroup,ownOu,foreignOu,reader:new DirectoryReader(database,{issuer,revalidate:fixture.revalidate})};
}
test('ordinary directory collections, aggregate search and totals expose only the actual original tenant despite global administration',async()=>{
 const fixture=await directoryFixture();await user();await group();await ou();const token='Bearer original';
 const users=await fixture.reader.users({},fixture.user,token);assert.equal(users.total,2);assert.deepEqual(new Set(users.users.map(row=>row.id)),new Set([fixture.actor.identity,fixture.target]));
 assert.deepEqual((await fixture.reader.groups({},fixture.user,token)).groups.map(row=>row.id),[fixture.ownGroup]);assert.equal((await fixture.reader.ous({},fixture.user,token)).total,1);
 const search=await fixture.reader.search({},fixture.user,token);assert.equal(search.total,3);assert.equal(JSON.stringify(search).includes(fixture.foreign.identity),false);assert.equal(JSON.stringify(search).includes(fixture.foreignGroup),false);
});
test('ownership predicates apply before actual user counts, literal filters and pagination rather than after a global SQL page',async()=>{
 const fixture=await directoryFixture();const own=[];const foreign=[];for(let index=0;index<28;index++){own.push(await user());foreign.push(await user());}
 await adoptTenant(database,schema,fixture.actor.tenant,manifest('user',...own));await adoptTenant(database,schema,fixture.foreign.tenant,manifest('user',...foreign));await pool.query('UPDATE users SET title=$2,enabled=false WHERE id=ANY($1::uuid[])',[own,'Literal %_ scoped term']);
 const first=await fixture.reader.users({},fixture.user,'Bearer original');const second=await fixture.reader.users({page:'2'},fixture.user,'Bearer original');assert.equal(first.total,30);assert.equal(first.users.length,25);assert.equal(second.users.length,5);
 for(const result of[first,second])assert.equal(result.users.some(row=>foreign.includes(row.id)),false);
 const selected=await fixture.reader.users({search:'%_',enabled:'false',limit:'100'},fixture.user,'Bearer original');assert.equal(selected.total,28);assert.equal(selected.users.length,28);
});
test('foreign, unowned and missing user/group/OU details and role history have the same not-found boundary',async()=>{
 const fixture=await directoryFixture();const unknown={user:await user(),group:await group(),ou:await ou()};
 for(const[kind,foreign]of[['user',fixture.foreign.identity],['group',fixture.foreignGroup],['ou',fixture.foreignOu]]){
  for(const target of[foreign,unknown[kind],randomUUID()])await assert.rejects(fixture.reader[kind](target,{},fixture.user,'Bearer original'),error=>error.status===404);
 }
 for(const target of[fixture.foreign.identity,unknown.user,randomUUID()])await assert.rejects(fixture.reader.roles(target,{},fixture.user,'Bearer original'),error=>error.status===404);
 assert.equal((await fixture.reader.user(fixture.target,{},fixture.user,'Bearer original')).id,fixture.target);assert.equal((await fixture.reader.roles(fixture.actor.identity,{},fixture.user,'Bearer original')).assignments[0].role,'admin');
});
test('ordinary group views never disclose a retained foreign historical member identifier',async()=>{
 const fixture=await directoryFixture();await pool.query('INSERT INTO group_members(group_id,user_id) VALUES($1,$2)',[fixture.ownGroup,fixture.target]);
 await pool.query('ALTER TABLE group_members DISABLE TRIGGER aaa_identity_tenant_membership_guard');try{await pool.query('INSERT INTO group_members(group_id,user_id) VALUES($1,$2)',[fixture.ownGroup,fixture.foreign.identity]);}finally{await pool.query('ALTER TABLE group_members ENABLE TRIGGER aaa_identity_tenant_membership_guard');}
 const group=await fixture.reader.group(fixture.ownGroup,{},fixture.user,'Bearer original');assert.deepEqual(group.members,[fixture.target]);assert.equal(JSON.stringify(await fixture.reader.search({},fixture.user,'Bearer original')).includes(fixture.foreign.identity),false);
});
test('the actual OU forest contains only coherent owned parent-child relationships',async()=>{
 const fixture=await directoryFixture();const child=await ou();await adoptTenant(database,schema,fixture.actor.tenant,manifest('ou',child));await pool.query('UPDATE ous SET parent_id=$2 WHERE id=$1',[child,fixture.ownOu]);
 const result=await fixture.reader.ous({},fixture.user,'Bearer original');assert.equal(result.total,2);assert.equal(result.tree.length,1);assert.equal(result.tree[0].children[0].id,child);assert.equal(JSON.stringify(result).includes(fixture.foreignOu),false);
});
test('a foreign historical OU parent produces no guessed root or leaked parent UUID',async()=>{
 const fixture=await directoryFixture();await pool.query('ALTER TABLE ous DISABLE TRIGGER identity_tenant_ou_guard');try{await pool.query('UPDATE ous SET parent_id=$2 WHERE id=$1',[fixture.ownOu,fixture.foreignOu]);}finally{await pool.query('ALTER TABLE ous ENABLE TRIGGER identity_tenant_ou_guard');}
 for(const read of[()=>fixture.reader.ous({},fixture.user,'Bearer original'),()=>fixture.reader.ou(fixture.ownOu,{},fixture.user,'Bearer original')])await assert.rejects(read(),error=>error.status===503&&!error.message.includes(fixture.foreignOu));
});
test('an actual same-owner OU cycle is rejected without recursive traversal or a fabricated forest',async()=>{
 const fixture=await directoryFixture();const child=await ou();await adoptTenant(database,schema,fixture.actor.tenant,manifest('ou',child));await pool.query('UPDATE ous SET parent_id=$2 WHERE id=$1',[child,fixture.ownOu]);await pool.query('UPDATE ous SET parent_id=$2 WHERE id=$1',[fixture.ownOu,child]);
 await assert.rejects(fixture.reader.ous({},fixture.user,'Bearer original'),error=>error.status===503);
});
test('revocation or source outage after actual directory SQL discards data rather than returning an admission-time snapshot',async()=>{
 for(const outage of[false,true]){const fixture=await directoryFixture();fixture.live.onCheck=async number=>{if(number===2){if(outage)throw Object.assign(new Error('Actual owned authority outage'),{status:503});fixture.live.revoked=true;}};
  await assert.rejects(fixture.reader.users({},fixture.user,'Bearer original'),error=>error.status===(outage?503:401));assert.equal(fixture.live.checks,2);
 }
});
test('original revocation during an observed real OU read lock wait cannot release the resulting records',async()=>{
 const fixture=await directoryFixture();const blocker=await pool.connect();let pending;
 try{await blocker.query('BEGIN');await blocker.query('LOCK TABLE ous IN ACCESS EXCLUSIVE MODE');pending=fixture.reader.ous({},fixture.user,'Bearer original');pending.catch(()=>{});let waiting=false;
  for(let attempt=0;attempt<100;attempt++){waiting=(await pool.query("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'SELECT id,name,description,parent_id,%') AS waiting")).rows[0].waiting;if(waiting)break;await new Promise(resolve=>setTimeout(resolve,5));}assert.equal(waiting,true);
  fixture.live.revoked=true;await blocker.query('COMMIT');await assert.rejects(pending,error=>error.status===401);
 }finally{await blocker.query('ROLLBACK');blocker.release();if(pending)await pending.catch(()=>{});}
});
test('read counts and records remain in one actual repeatable-read snapshot across concurrent owned insertions',async()=>{
 const fixture=await directoryFixture();let inserted;const wrapped={isAvailable:()=>true,transaction:(operation,options)=>database.transaction(client=>operation({query:async(sql,values)=>{const result=await client.query(sql,values);if(sql.startsWith('SELECT COUNT(*) AS count FROM users'))inserted=await userTarget(fixture.actor.tenant);return result;}}),options)};
 const result=await new DirectoryReader(wrapped,{issuer,revalidate:fixture.revalidate}).users({},fixture.user,'Bearer original');assert.equal(result.total,2);assert.equal(result.users.length,2);assert.equal(result.users.some(row=>row.id===inserted),false);assert.equal((await fixture.reader.users({},fixture.user,'Bearer original')).total,3);
});
test('the actual directory transaction is read-only and a positive proof cannot authorize SQL writes',async()=>{
 const fixture=await directoryFixture();await assert.rejects(fixture.reader.read(['users.read'],fixture.user,'Bearer original',client=>client.query('UPDATE users SET title=$1 WHERE id=$2',['Not a read',fixture.target])),error=>error.code==='25006');assert.equal((await pool.query('SELECT title FROM users WHERE id=$1',[fixture.target])).rows[0].title,null);
});
test('stale canonical identity or mismatched tenant proof cannot borrow a currently enabled local tenant',async()=>{
 const fixture=await directoryFixture();const foreign=await state(fixture.foreign.identity);const mismatched=new DirectoryReader(database,{issuer,revalidate:async()=>foreign.tenant});await assert.rejects(mismatched.users({},fixture.user,'Bearer original'),error=>error.status===401);
 const original=await state(fixture.actor.identity);await pool.query('UPDATE users SET authorization_revision=authorization_revision+1 WHERE id=$1',[fixture.actor.identity]);const stale=new DirectoryReader(database,{issuer,revalidate:async()=>original.tenant});await assert.rejects(stale.users({},fixture.user,'Bearer original'),error=>error.status===401);
});
test('query-selected tenants, ignored LDAP selectors, workloads and legacy unbound actors cannot select a directory scope',async()=>{
 const fixture=await directoryFixture();for(const selector of[{tenantId:fixture.foreign.tenant},{issuer:'https://other.test'},{filter:'(objectClass=*)'},{base:'dc=other'},{scope:'sub'}]){
  await assert.rejects(fixture.reader.search(selector,fixture.user,'Bearer original'),error=>error.status===400);await assert.rejects(fixture.reader.groups(selector,fixture.user,'Bearer original'),error=>error.status===400);
 }
 for(const user of[{...fixture.user,actor_type:'application'},{...fixture.user,identity_authorization:undefined},{...fixture.user,roles:['user']}])await assert.rejects(fixture.reader.users({},user,'Bearer original'),error=>error.status===403);
 assert.equal(fixture.live.checks,0);
});
test('tenant pause after actual directory SQL prevents result delivery without reviving old origin on resume',async()=>{
 const fixture=await directoryFixture();fixture.live.onCheck=async number=>{if(number===2)await enableTenant(database,schema,fixture.actor.tenant,false);};
 await assert.rejects(fixture.reader.users({},fixture.user,'Bearer original'),error=>error.status===401);await enableTenant(database,schema,fixture.actor.tenant,true);fixture.live.onCheck=null;await assert.rejects(fixture.reader.users({},fixture.user,'Bearer original'),error=>error.status===401);
});
const state=identity=>new AuthorizationState(database).state(issuer,identity);
const snapshot=identity=>new UserSnapshotStore(database).snapshot(identity,{issuer,subject:identity});
async function owned(){const tenant=await provisionTenant(database,schema,{enabled:true});const identity=await user();await adoptTenant(database,schema,tenant,manifest('user',identity));return{tenant,identity};}
async function review(client){await client.query("SELECT set_config('opendirectory.tenant_review','explicit-offline-owner-review',true),set_config('opendirectory.tenant_reason','Explicit independent native tenant transition review',true)");}
async function count(table){return(await pool.query('SELECT count(*)::int AS count FROM '+table)).rows[0].count;}

test('migration invents no default tenant and unowned existing identities cannot authorize or produce positive eligibility',async()=>{
 const identity=await user();assert.equal(await count('identity_tenants'),0);assert.equal(await count('identity_tenant_ownership'),0);
 assert.equal((await state(identity)).active,false);assert.equal((await snapshot(identity)).enabled,false);assert.equal((await pool.query('SELECT enabled FROM users WHERE id=$1',[identity])).rows[0].enabled,true);
 const unowned=await group();await assert.rejects(new GroupSnapshotStore(database).snapshot(unowned),error=>error.status===404);
});
test('reviewed adoption plus explicit tenant enablement activates only a new identity and eligibility generation',async()=>{
 const identity=await user();const before=(await pool.query('SELECT authorization_revision,eligibility_revision FROM users WHERE id=$1',[identity])).rows[0];
 const tenant=await provisionTenant(database,schema);await adoptTenant(database,schema,tenant,manifest('user',identity));assert.equal((await state(identity)).active,false);
 await enableTenant(database,schema,tenant,true);const active=await state(identity);assert.equal(active.active,true);assert.ok(BigInt(active.context.revision)>BigInt(before.authorization_revision));assert.ok(BigInt((await snapshot(identity)).revision)>BigInt(before.eligibility_revision));
});
test('tenant pause and re-enable fence old generations without rewriting the individual enabled flag',async()=>{
 const context=await owned();const before=await state(context.identity);const eligibility=await snapshot(context.identity);await enableTenant(database,schema,context.tenant,false);
 assert.equal((await state(context.identity)).active,false);const paused=await snapshot(context.identity);assert.equal(paused.enabled,false);assert.ok(BigInt(paused.revision)>BigInt(eligibility.revision));
 assert.equal((await pool.query('SELECT enabled FROM users WHERE id=$1',[context.identity])).rows[0].enabled,true);
 await enableTenant(database,schema,context.tenant,true);const resumed=await state(context.identity);assert.equal(resumed.active,true);assert.notEqual(resumed.context.revision,before.context.revision);assert.notEqual((await snapshot(context.identity)).revision,eligibility.revision);
});
test('disabled people remain disabled after their tenant is resumed rather than inheriting a guessed prior state',async()=>{
 const context=await owned();await pool.query('UPDATE users SET enabled=false WHERE id=$1',[context.identity]);await enableTenant(database,schema,context.tenant,false);await enableTenant(database,schema,context.tenant,true);
 assert.equal((await state(context.identity)).active,false);assert.equal((await snapshot(context.identity)).enabled,false);
});
test('tenant identity and ownership cannot be retargeted, moved, removed or enabled by an unreviewed update',async()=>{
 const context=await owned();for(const sql of ["UPDATE identity_tenants SET external_key='retarget',version=version+1",'DELETE FROM identity_tenants','UPDATE identity_tenant_ownership SET tenant_id=gen_random_uuid()','DELETE FROM identity_tenant_ownership','UPDATE identity_tenants SET enabled=false,version=version+1'])await assert.rejects(pool.query(sql),error=>['42501','23514'].includes(error.code));
 await assert.rejects(enableTenant(database,schema,context.tenant,false,1),/Exact current/);assert.equal((await state(context.identity)).active,true);
});
test('adoption uses a complete exact bounded manifest and cannot invent resources or silently adopt a second incarnation',async()=>{
 const tenant=await provisionTenant(database,schema);const identity=await user();for(const changed of [[],[{kind:'user',resourceId:'legacy'}],[{kind:'device',resourceId:identity}],[{kind:'user',resourceId:identity,admin:true}],manifest('user',randomUUID()),manifest('user',identity,identity)])await assert.rejects(adoptTenant(database,schema,tenant,changed));
 assert.equal(await count('identity_tenant_ownership'),0);await adoptTenant(database,schema,tenant,manifest('user',identity));await assert.rejects(adoptTenant(database,schema,tenant,manifest('user',identity)),error=>error.code==='23505');
});
test('existing memberships require coherent reviewed adoption rather than making unknown owners match',async()=>{
 const tenant=await provisionTenant(database,schema);const identity=await user();const team=await group();await pool.query('INSERT INTO group_members(group_id,user_id) VALUES($1,$2)',[team,identity]);
 await assert.rejects(adoptTenant(database,schema,tenant,manifest('user',identity)),/complete reviewed/);await assert.rejects(adoptTenant(database,schema,tenant,manifest('group',team)),/fully resolved/);
 assert.equal(await count('identity_tenant_ownership'),0);await adoptTenant(database,schema,tenant,[...manifest('user',identity),...manifest('group',team)]);assert.equal(await count('identity_tenant_ownership'),2);
});
test('different owned tenants cannot acquire a cross-owner membership even through direct SQL or global administrative role labels',async()=>{
 const first=await owned();const second=await owned();const team=await group();await adoptTenant(database,schema,first.tenant,manifest('group',team));
 await pool.query('INSERT INTO group_members(group_id,user_id) VALUES($1,$2)',[team,first.identity]);await assert.rejects(pool.query('INSERT INTO group_members(group_id,user_id) VALUES($1,$2)',[team,second.identity]),error=>error.code==='23514');
 await assert.rejects(pool.query('UPDATE group_members SET user_id=$2 WHERE group_id=$1',[team,second.identity]),error=>['23514','42501'].includes(error.code));assert.equal((await pool.query('SELECT count(*)::int AS count FROM group_members')).rows[0].count,1);
});
test('canonical application-target metadata rejects foreign ownership and reveals no foreign target revision',async()=>{
 const first=await owned();const second=await owned();const team=await group();await adoptTenant(database,schema,second.tenant,manifest('group',team));const source=new AuthorizationState(database);
 await database.transaction(async client=>{await client.query("SELECT set_config('opendirectory.actor','Explicit owned global administrative fixture',true)");await client.query("INSERT INTO identity_role_assignments(user_id,role,reason) VALUES($1,'admin','Explicit reviewed global role cannot override resource ownership')",[first.identity]);});assert.ok((await state(first.identity)).roles.includes('admin'));
 assert.equal((await source.target('user',first.identity,first.identity)).active,true);
 for(const[kind,id]of [['user',second.identity],['group',team]])assert.deepEqual(await source.target(kind,id,first.identity),{schemaVersion:1,targetType:kind,targetId:id,active:false,revision:null,actorIsMember:false});
});
test('tenant pause invalidates the group frame and returns known inactive members without pretending the source is absent',async()=>{
 const context=await owned();const team=await group();await adoptTenant(database,schema,context.tenant,manifest('group',team));await pool.query('INSERT INTO group_members(group_id,user_id) VALUES($1,$2)',[team,context.identity]);
 const source=new GroupSnapshotStore(database);const before=await source.snapshot(team);assert.deepEqual(before.memberIds,[context.identity]);await enableTenant(database,schema,context.tenant,false);
 const paused=await source.snapshot(team);assert.deepEqual(paused.memberIds,[]);assert.deepEqual(paused.inactiveMemberIds,[context.identity]);assert.ok(BigInt(paused.revision)>BigInt(before.revision));
});
test('OU ownership must be coherent and neither existing nor new parents can cross tenants',async()=>{
 const first=await provisionTenant(database,schema);const second=await provisionTenant(database,schema);const parent=await ou();const child=await ou();await pool.query('UPDATE ous SET parent_id=$2 WHERE id=$1',[child,parent]);
 await assert.rejects(adoptTenant(database,schema,first,manifest('ou',parent)),/complete reviewed/);await adoptTenant(database,schema,first,manifest('ou',parent,child));const foreign=await ou();await adoptTenant(database,schema,second,manifest('ou',foreign));
 await assert.rejects(pool.query('UPDATE ous SET parent_id=$2 WHERE id=$1',[child,foreign]),error=>error.code==='23514');
 await assert.rejects(pool.query('INSERT INTO ous(id,name,parent_id) VALUES($1,$2,$3)',[randomUUID(),'Unowned child',parent]),error=>error.code==='23514');
});
test('adoption and a concurrent membership addition serialize actual ownership before either can acknowledge a mixed component',async()=>{
 const tenant=await provisionTenant(database,schema);const team=await group();const identity=await user();const first=await pool.connect();let pending;
 try{await first.query('BEGIN');await review(first);await first.query('SELECT identity_tenant_adopt($1,1,$2)',[tenant,JSON.stringify(manifest('group',team))]);
  pending=pool.query('INSERT INTO group_members(group_id,user_id) VALUES($1,$2)',[team,identity]);pending.catch(()=>{});let waiting=false;
  for(let attempt=0;attempt<200;attempt++){waiting=(await pool.query("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event='advisory' AND query LIKE 'INSERT INTO group_members%') AS waiting")).rows[0].waiting;if(waiting)break;await new Promise(resolve=>setTimeout(resolve,10));}assert.equal(waiting,true);
  await first.query('COMMIT');await assert.rejects(pending,error=>error.code==='23514');assert.equal(await count('group_members'),0);
 }finally{await first.query('ROLLBACK');first.release();if(pending)await pending.catch(()=>{});}
});
test('missing mandatory tenant audit or outbox rolls back adoption rather than leaving a new sign-in authority',async()=>{
 for(const table of ['identity_tenant_events','identity_tenant_outbox']){const tenant=await provisionTenant(database,schema,{enabled:true});const identity=await user();await pool.query(`ALTER TABLE ${table} RENAME TO withheld_tenant_evidence`);
  try{await assert.rejects(adoptTenant(database,schema,tenant,manifest('user',identity)));}finally{await pool.query(`ALTER TABLE withheld_tenant_evidence RENAME TO ${table}`);}assert.equal((await state(identity)).active,false);assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_tenant_ownership WHERE resource_id=$1',[identity])).rows[0].count,0);
 }
});
test('identity, eligibility and tenant evidence all roll back a tenant pause when mandatory receiving storage fails',async()=>{
 for(const table of ['identity_user_audit','identity_user_outbox','identity_authorization_audit','identity_tenant_events','identity_tenant_outbox']){const context=await owned();const before=await state(context.identity);await pool.query(`ALTER TABLE ${table} RENAME TO withheld_tenant_pause`);
  try{await assert.rejects(enableTenant(database,schema,context.tenant,false));}finally{await pool.query(`ALTER TABLE withheld_tenant_pause RENAME TO ${table}`);}assert.deepEqual(await state(context.identity),before);
 }
});
test('derived effective eligibility outbox agrees with paused parent authority even when an individual flag is toggled',async()=>{
 const context=await owned();await enableTenant(database,schema,context.tenant,false);await pool.query('UPDATE users SET enabled=false WHERE id=$1',[context.identity]);await pool.query('UPDATE users SET enabled=true WHERE id=$1',[context.identity]);
 const events=(await pool.query('SELECT payload FROM identity_user_outbox WHERE user_id=$1 ORDER BY revision DESC',[context.identity])).rows;assert.equal(events[0].payload.enabled,false);assert.equal(events[1].payload.enabled,false);assert.equal((await snapshot(context.identity)).enabled,false);
});
test('clients cannot forge a source generation and ordinary profile edits do not invent new authorization generations',async()=>{
 const context=await owned();const before=await snapshot(context.identity);const authority=await state(context.identity);await pool.query('UPDATE users SET tenant_generation=0,eligibility_revision=1,title=$2 WHERE id=$1',[context.identity,'Normal profile metadata']);
 assert.deepEqual(await snapshot(context.identity),before);assert.deepEqual(await state(context.identity),authority);
});
test('owned deleted identifiers and tenant ownership are retained for users, groups and OUs',async()=>{
 const context=await owned();const team=await group();const unit=await ou();await adoptTenant(database,schema,context.tenant,[...manifest('group',team),...manifest('ou',unit)]);
 for(const[table,id]of [['users',context.identity],['groups',team],['ous',unit]])await pool.query('DELETE FROM '+table+' WHERE id=$1',[id]);assert.equal(await count('identity_tenant_retirements'),3);assert.equal(await count('identity_tenant_ownership'),3);
 await assert.rejects(pool.query('INSERT INTO ous(id,name) VALUES($1,$2)',[unit,'Retargeted old namespace']),error=>error.code==='23514');assert.equal((await new UserSnapshotStore(database).snapshot(context.identity,{issuer,subject:context.identity},true)).deleted,true);
});
test('an actual limited database login cannot adopt, enable, forge review evidence or impersonate the owner through SET ROLE',async()=>{
 const tenant=await provisionTenant(database,schema);const identity=await user();const role='tenant_limited_'+randomUUID().replaceAll('-','');const password='owned-'+randomUUID();let limited;
 await admin.query(`CREATE ROLE ${role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOINHERIT PASSWORD '${password}'`);
 try{await pool.query(`GRANT USAGE ON SCHEMA ${schema} TO ${role};GRANT EXECUTE ON FUNCTION identity_tenant_adopt(uuid,bigint,jsonb),identity_tenant_review(oid) TO ${role}`);const address=new URL(process.env.IDENTITY_TEST_DATABASE_URL);address.username=role;address.password=password;limited=new Pool({connectionString:address.toString(),max:1,options:`-c search_path=${schema},public`});
  const bound=await limited.connect();try{await bound.query('BEGIN');await review(bound);await assert.rejects(bound.query('SELECT identity_tenant_adopt($1,1,$2)',[tenant,JSON.stringify(manifest('user',identity))]),error=>error.code==='42501'&&error.message==='Explicit actual-owner tenant review required');}finally{await bound.query('ROLLBACK');bound.release();}
  const client=await pool.connect();try{await client.query('BEGIN');await client.query(`SET LOCAL ROLE ${role}`);await review(client);await assert.rejects(client.query('SELECT identity_tenant_adopt($1,1,$2)',[tenant,JSON.stringify(manifest('user',identity))]),error=>error.code==='42501'&&error.message==='Explicit actual-owner tenant review required');}finally{await client.query('ROLLBACK');client.release();}
  await assert.rejects(limited.query('DELETE FROM identity_tenant_events'),error=>error.code==='42501');
 }finally{await limited?.end();await pool.query(`DROP OWNED BY ${role}`);await admin.query(`DROP ROLE ${role}`);}
});
test('temporary shadow tables cannot substitute an enabled tenant or change an actual owner binding',async()=>{
 const context=await owned();await enableTenant(database,schema,context.tenant,false);const client=await pool.connect();try{
  await client.query('CREATE TEMP TABLE identity_tenants(id uuid,enabled boolean);CREATE TEMP TABLE identity_tenant_ownership(resource_kind text,resource_id uuid,tenant_id uuid)');await client.query('INSERT INTO pg_temp.identity_tenants VALUES($1,true)',[context.tenant]);await client.query("INSERT INTO pg_temp.identity_tenant_ownership VALUES('user',$1,$2)",[context.identity,randomUUID()]);
  assert.equal((await client.query('SELECT identity_tenant_user_enabled($1) AS enabled',[context.identity])).rows[0].enabled,false);assert.equal((await client.query("SELECT identity_tenant_id('user',$1) AS tenant",[context.identity])).rows[0].tenant,context.tenant);
 }finally{await client.query('DROP TABLE pg_temp.identity_tenants,pg_temp.identity_tenant_ownership');client.release();}
});
test('migration replay preserves ownership, generations and evidence and cannot restore old paused authority',async()=>{
 const context=await owned();await enableTenant(database,schema,context.tenant,false);const before=(await pool.query('SELECT * FROM identity_tenant_ownership')).rows;const versions=(await pool.query('SELECT authorization_revision,eligibility_revision,tenant_generation FROM users')).rows;
 for(const file of ['004_user_eligibility.sql','005_authorization_generation.sql','024_tenant_ownership.sql'])await pool.query(fs.readFileSync(path.join(migrations,file),'utf8'));
 assert.deepEqual((await pool.query('SELECT * FROM identity_tenant_ownership')).rows,before);assert.deepEqual((await pool.query('SELECT authorization_revision,eligibility_revision,tenant_generation FROM users')).rows,versions);assert.equal((await state(context.identity)).active,false);
 await enableTenant(database,schema,context.tenant,true);assert.equal((await state(context.identity)).active,true);
});
test('resource deletion racing adoption cannot commit an owned namespace without a live resource or retained retirement',async()=>{
 const tenant=await provisionTenant(database,schema);for(const[kind,table,create]of [['user','users',user],['group','groups',group],['ou','ous',ou]]){
  for(let attempt=0;attempt<4;attempt++){
   const identity=await create();const results=await Promise.allSettled([adoptTenant(database,schema,tenant,manifest(kind,identity)),pool.query('DELETE FROM '+table+' WHERE id=$1',[identity])]);assert.equal(results[1].status,'fulfilled');
   const adopted=(await pool.query('SELECT tenant_id FROM identity_tenant_ownership WHERE resource_kind=$1 AND resource_id=$2',[kind,identity])).rows[0];
   if(adopted)assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_tenant_retirements WHERE resource_kind=$1 AND resource_id=$2',[kind,identity])).rows[0].count,1);
  }
 }
});
test('a reviewed tenant still starts disabled and raw generation input cannot retarget its identity or reset authority',async()=>{
 const tenant=await provisionTenant(database,schema);const before=(await pool.query('SELECT * FROM identity_tenants WHERE id=$1',[tenant])).rows[0];assert.equal(before.enabled,false);
 await assert.rejects(tenantScript(database,schema,'tenant-provision.sql',{tenant_id:randomUUID(),external_key:'bad key',display_name:'Bounded name',reason:'Explicit reviewed malformed provision rejection'}),error=>error.code==='23514');
 const client=await pool.connect();try{await client.query('BEGIN');await review(client);const changed=(await client.query('UPDATE identity_tenants SET enabled=true,version=version+1,generation=1 WHERE id=$1 RETURNING generation',[tenant])).rows[0];assert.ok(BigInt(changed.generation)>BigInt(before.generation));await client.query('COMMIT');}finally{await client.query('ROLLBACK');client.release();}
 assert.equal((await pool.query('SELECT external_key FROM identity_tenants WHERE id=$1',[tenant])).rows[0].external_key,before.external_key);
});
test('canonical user, group and OU UUID updates cannot strand or retarget an immutable owner namespace',async()=>{
 const context=await owned();const team=await group();const unit=await ou();await adoptTenant(database,schema,context.tenant,[...manifest('group',team),...manifest('ou',unit)]);
 for(const[table,id]of [['users',context.identity],['groups',team],['ous',unit]])await assert.rejects(pool.query('UPDATE '+table+' SET id=$2 WHERE id=$1',[id,randomUUID()]),error=>error.code==='42501');assert.equal(await count('identity_tenant_ownership'),3);
});
test('a retained foreign legacy membership cannot become a positive group-license source even after privileged import bypassed validation',async()=>{
 const first=await owned();const second=await owned();const team=await group();await adoptTenant(database,schema,first.tenant,manifest('group',team));
 await pool.query('ALTER TABLE group_members DISABLE TRIGGER aaa_identity_tenant_membership_guard');try{await pool.query('INSERT INTO group_members(group_id,user_id) VALUES($1,$2)',[team,second.identity]);}finally{await pool.query('ALTER TABLE group_members ENABLE TRIGGER aaa_identity_tenant_membership_guard');}
 await assert.rejects(new GroupSnapshotStore(database).snapshot(team),error=>error.status===503&&error.message==='Group contains foreign retained identities');
});
