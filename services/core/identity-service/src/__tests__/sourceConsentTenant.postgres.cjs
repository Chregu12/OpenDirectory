'use strict';

const {test,before,beforeEach,after}=require('node:test');
const assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const fs=require('node:fs');
const path=require('node:path');
const {Pool}=require('pg');
const {GroupSourceGrants,tag}=require('../GroupSourceGrants');
const {GroupSnapshotStore}=require('../GroupSnapshotStore');
const {AuthorizationState}=require('../AuthorizationState');
const {readRoleState}=require('../RoleState');
const {bootstrapRole}=require('../../scripts/bootstrap-role');
const {provisionTenant,adoptTenant,enableTenant}=require('../../../../../scripts/lib/tenant-ownership-fixture.cjs');
const {SOURCE_SCOPE}=require('../../../../../packages/group-license-lease-contract');
const schema='source_consent_tenant_'+randomUUID().replaceAll('-','');
const administration=new Pool({connectionString:process.env.IDENTITY_TEST_DATABASE_URL,max:1});
const issuer='https://source-consent.test';const humanBearer='Bearer original-source-operator';const workloadBearer='Bearer exact-source-workload';
const reason='Explicit retained same-tenant group source consent';
let pool;let database;let queries;
before(async()=>{
 await administration.query('CREATE SCHEMA '+schema);
 pool=new Pool({connectionString:process.env.IDENTITY_TEST_DATABASE_URL,max:8,options:`-c search_path=${schema},public`});
 database={getClient:()=>pool.connect(),query:(...args)=>pool.query(...args),transaction:async(operation,options={})=>{
  const client=await pool.connect();try{
   await client.query(options.readOnly?'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY':'BEGIN');await client.query("SET LOCAL lock_timeout='2s';SET LOCAL statement_timeout='10s'");
   if(options.actor)await client.query("SELECT set_config('opendirectory.actor',$1,true)",[options.actor]);
   const result=await operation({query:async(...args)=>{queries.push(args[0]);return client.query(...args);}});await client.query('COMMIT');return result;
  }catch(error){await client.query('ROLLBACK');throw error;}finally{client.release();}
 }};
 const migrations=path.join(__dirname,'../../migrations');
 for(const file of fs.readdirSync(migrations).filter(file=>file.endsWith('.sql')).sort())await pool.query(fs.readFileSync(path.join(migrations,file),'utf8'));
});
beforeEach(async()=>{queries=[];await pool.query('TRUNCATE identity_tenants,users,groups,ous,identity_role_assignments,identity_group_source_grants,identity_role_review_policies CASCADE');});
after(async()=>{await pool.end();await administration.query('DROP SCHEMA '+schema+' CASCADE');await administration.end();});
async function person(role='license-scope-administrator',tenant){
 if(tenant===undefined)tenant=await provisionTenant(database,schema,{enabled:true});
 const userId=randomUUID();const subject='source-person-'+randomUUID();
 await pool.query('INSERT INTO users(id,username,email) VALUES($1,$2,$3)',[userId,subject,subject+'@test.invalid']);
 await pool.query('INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES($1,$2,$3)',[issuer,subject,userId]);
 if(tenant)await adoptTenant(database,schema,tenant,[{kind:'user',resourceId:userId}]);
 await bootstrapRole(database,{userId,role,duration:3600,reason});
 const source=await new AuthorizationState(database).state(issuer,subject);const state=await database.transaction(client=>readRoleState(client,userId),{readOnly:true});
 const row=(await pool.query('SELECT account.authorization_revision AS revision,link.authorization_revision AS link_revision FROM users account JOIN identity_subject_links link ON link.user_id=account.id WHERE account.id=$1',[userId])).rows[0];
 const authTime=Math.floor(Date.now()/1000);const context=source.context||{userId,revision:String(row.revision),linkRevision:String(row.link_revision),rolesRevision:state.rolesRevision};
 return{tenant,userId,user:{actor_type:'user',iss:issuer,sub:subject,client_id:'source-human-console',roles:state.roles,identity_authorization:context,jti:randomUUID(),exp:authTime+300,auth_time:authTime,amr:['pwd','otp'],mfa_authorization:{schemaVersion:1,userId,revision:'1',authTime,methods:['pwd','otp']}}};
}
async function group(tenant){
 const id=randomUUID();await pool.query('INSERT INTO groups(id,name) VALUES($1,$2)',[id,'Source group '+id]);
 await adoptTenant(database,schema,tenant,[{kind:'group',resourceId:id}]);return id;
}
async function fixture(){
 const operator=await person();const reader=await person('license-scope-reader',operator.tenant);const groupId=await group(operator.tenant);const clientId='exact-source-'+randomUUID();
 const binding={schemaVersion:1,clientId,revision:'1',enabled:true,canReadGroupSources:true};const state={checks:0,onCheck:null};
 const revalidate=async(user,bearer)=>{assert.equal(bearer,user.actor_type==='application'?workloadBearer:humanBearer);state.checks++;if(state.onCheck)await state.onCheck(state.checks,user);};
 const store=new GroupSourceGrants(database,{clients:{issuer,get:async identifier=>{assert.equal(identifier,clientId);return binding;}},revalidate});
 const body={groupId,clientId,expectedClientRevision:'1',expiresAt:new Date(Date.now()+3600000).toISOString(),reason,acknowledgeReadScope:true};
 const workload={actor_type:'application',token_use:'access',iss:issuer,sub:clientId,client_id:clientId,client_revision:'1',scope:SOURCE_SCOPE,permissions:[SOURCE_SCOPE]};
 return{operator,reader,groupId,binding,state,store,body,workload,create:()=>store.create(body,operator.user,humanBearer),snapshot:()=>store.snapshot(groupId,workload,workloadBearer)};
}
async function evidence(){return(await pool.query('SELECT (SELECT count(*)::int FROM identity_group_source_grants) AS grants,(SELECT count(*)::int FROM identity_group_source_audit) AS audit')).rows[0];}
async function legacyConsent(context,groupId,creator=context.operator){
 return database.transaction(async client=>{
  await context.store.context(client,creator.user,'create',reason,context.binding);
  return(await client.query('INSERT INTO identity_group_source_grants(group_id,issuer,client_id,client_revision,created_by,expires_at) VALUES($1,$2,$3,1,$4,$5) RETURNING *,identity_group_source_now() AS observed_at',[groupId,issuer,context.binding.clientId,creator.userId,context.body.expiresAt])).rows[0];
 });
}
test('same-tenant human CRUD retains actual authority, source evidence and the unchanged explicit workload frame',async()=>{
 const context=await fixture();const grant=await context.create();
 assert.equal((await context.store.list(context.groupId,context.reader.user,humanBearer)).grants[0].id,grant.id);
 assert.equal((await context.store.get(grant.id,context.reader.user,humanBearer)).id,grant.id);
 const snapshot=await context.snapshot();assert.equal(snapshot.viewerUserId,null);assert.deepEqual(snapshot.sourceAuthorization,{grantId:grant.id,version:'1',issuer,clientId:context.binding.clientId,clientRevision:'1',expiresAt:grant.expiresAt});
 assert.deepEqual(await evidence(),{grants:1,audit:1});
 const revoked=await context.store.revoke(grant.id,tag(grant),{reason,acknowledgeReadScope:true},context.operator.user,humanBearer);assert.equal(revoked.state,'revoked');
 await assert.rejects(context.snapshot(),error=>error.status===403);assert.deepEqual(await evidence(),{grants:1,audit:2});
});
test('foreign groups and known consent IDs are hidden before foreign group or consent locks',async()=>{
 const own=await fixture();const foreign=await fixture();const grant=await foreign.create();const before=await evidence();const blocker=await pool.connect();
 try{
  await blocker.query('BEGIN');await blocker.query('SELECT id FROM groups WHERE id=$1 FOR UPDATE',[foreign.groupId]);await blocker.query('SELECT id FROM identity_group_source_grants WHERE id=$1 FOR UPDATE',[grant.id]);const started=Date.now();
  await assert.rejects(own.store.list(foreign.groupId,own.reader.user,humanBearer),error=>error.status===404);
  await assert.rejects(own.store.get(grant.id,own.reader.user,humanBearer),error=>error.status===404);
  await assert.rejects(own.store.create({...own.body,groupId:foreign.groupId},own.operator.user,humanBearer),error=>error.status===404);
  await assert.rejects(own.store.revoke(grant.id,tag(grant),{reason,acknowledgeReadScope:true},own.operator.user,humanBearer),error=>error.status===404);
  assert.ok(Date.now()-started<1500);assert.deepEqual(await evidence(),before);
 }finally{await blocker.query('ROLLBACK');blocker.release();}
});
test('claimed source duties cannot replace the actual canonical role state',async()=>{
 const context=await fixture();const ordinary=await person('user',context.operator.tenant);const forged={...ordinary.user,roles:['license-scope-administrator'],permissions:['licenses.sources.read','licenses.sources.manage']};const before=await evidence();
 await assert.rejects(context.store.list(context.groupId,forged,humanBearer),error=>error.status===401);
 await assert.rejects(context.store.create(context.body,forged,humanBearer),error=>error.status===401);assert.deepEqual(await evidence(),before);
});
test('original bearer loss after consent DML rolls back the grant and mandatory source audit',async()=>{
 const context=await fixture();context.state.onCheck=async count=>{if(count===3){assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_group_source_grants')).rows[0].count,0);throw Object.assign(new Error('Original bearer revoked after DML'),{status:401});}};
 await assert.rejects(context.create(),error=>error.status===401);assert.deepEqual(await evidence(),{grants:0,audit:0});
});
test('a saved foreign-target legacy consent cannot authorize a workload or trigger membership refresh',async()=>{
 const context=await fixture();const foreign=await fixture();await legacyConsent(context,foreign.groupId);const before=queries.length;
 await assert.rejects(context.store.snapshot(foreign.groupId,context.workload,workloadBearer),error=>error.status===403);
 assert.equal(queries.slice(before).some(sql=>sql.includes('identity_membership_review_refresh')),false);
});
test('a source author without retained tenant ownership cannot authorize a legacy workload consent',async()=>{
 const context=await fixture();const unowned=await person('license-scope-administrator',null);await legacyConsent(context,context.groupId,unowned);const before=queries.length;
 await assert.rejects(context.snapshot(),error=>error.status===403);assert.equal(queries.slice(before).some(sql=>sql.includes('identity_membership_review_refresh')),false);
});
test('retained creator and group ownership permit negative hygiene after creator deletion, disabled members and target deletion',async()=>{
 const context=await fixture();const member=await person('user',context.operator.tenant);const grant=await context.create();
 await pool.query('INSERT INTO group_members(group_id,user_id) VALUES($1,$2)',[context.groupId,member.userId]);await pool.query('UPDATE users SET enabled=false WHERE id=$1',[member.userId]);await pool.query('DELETE FROM users WHERE id=$1',[context.operator.userId]);
 const disabled=await context.snapshot();assert.deepEqual(disabled.memberIds,[]);assert.deepEqual(disabled.inactiveMemberIds,[member.userId]);assert.equal(disabled.sourceAuthorization.grantId,grant.id);
 await pool.query('DELETE FROM groups WHERE id=$1',[context.groupId]);const deleted=await context.snapshot();assert.equal(deleted.deleted,true);assert.deepEqual(deleted.memberIds,[]);
 assert.equal((await context.store.get(grant.id,context.reader.user,humanBearer)).id,grant.id);
 assert.equal((await context.store.revoke(grant.id,tag(grant),{reason,acknowledgeReadScope:true},(await person('license-scope-administrator',context.reader.tenant)).user,humanBearer)).state,'revoked');
});
test('an initially disabled target tenant returns an explicit negative workload frame',async()=>{
 const context=await fixture();const member=await person('user',context.operator.tenant);await context.create();await pool.query('INSERT INTO group_members(group_id,user_id) VALUES($1,$2)',[context.groupId,member.userId]);
 await enableTenant(database,schema,context.operator.tenant,false);const snapshot=await context.snapshot();assert.deepEqual(snapshot.memberIds,[]);assert.deepEqual(snapshot.inactiveMemberIds,[member.userId]);
});
test('actual tenant disable and generation change between source authorizations discard the earlier frame',async()=>{
 const context=await fixture();await context.create();let changed=false;
 const guarded=new GroupSnapshotStore({transaction:(operation,options)=>database.transaction(client=>operation({query:async(sql,values)=>{
  if(sql==='SELECT identity_membership_review_refresh($1)'&&!changed){changed=true;await enableTenant(database,schema,context.operator.tenant,false);}return client.query(sql,values);
 }}),options)});context.store.snapshots=guarded;
 await assert.rejects(context.snapshot(),error=>error.status===409&&error.code==='source_target_tenant_changed');assert.equal(changed,true);
});
