'use strict';

const { test, before, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { Pool } = require('pg');
const { SignJWT, generateKeyPair, exportJWK } = require('jose');
const { GroupSnapshotStore } = require('../GroupSnapshotStore');
const { AuthorizationState } = require('../AuthorizationState');
const { RoleAuthentication, policyEtag } = require('../RoleAuthentication');
const { PrivilegedAccessPolicy, activationEtag } = require('../PrivilegedAccessPolicy');

const schema = `identity_test_${randomUUID().replaceAll('-', '')}`;
const clockSchema = schema + '_clock';
const administration = new Pool({ connectionString: process.env.IDENTITY_TEST_DATABASE_URL, max: 1 });
let database;
let snapshots;
let server;
let jwks;
let base;
let privateKey;
const issuer = 'https://identity.test';
const snapshotContent=snapshot=>Object.fromEntries(Object.entries(snapshot).filter(([key])=>!['observedAt','validUntil'].includes(key)));
const sourcePurpose='licenses.groups.derive';
test('an authorized source read waiting on its group can finish before concurrent consent withdrawal without a lock-order deadlock',async()=>{
 const fixture=await sourceFixture();const grant=await fixture.create();const blocker=await database.pool.connect();let reading;let withdrawing;
 try{await blocker.query('BEGIN');await blocker.query('SELECT id FROM groups WHERE id=$1 FOR UPDATE',[fixture.groupId]);reading=fixture.snapshot();reading.catch(()=>{});let waiting=false;
 for(let attempt=0;attempt<200;attempt++){waiting=(await database.query("SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query='SELECT identity_membership_review_refresh($1)'")).rows.length>0;if(waiting)break;await new Promise(resolve=>setTimeout(resolve,10));}assert.equal(waiting,true);
 withdrawing=fixture.store.revoke(grant.id,`"od-group-source:${grant.id}:1"`,{reason:'Concurrent exact source consent withdrawal',acknowledgeReadScope:true},fixture.actor,'Bearer original');withdrawing.catch(()=>{});waiting=false;
 for(let attempt=0;attempt<200;attempt++){waiting=(await database.query("SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'SELECT grants.*,identity_group_source_now() AS observed_at FROM identity_group_source_grants grants%FOR UPDATE OF grants'")).rows.length>0;if(waiting)break;await new Promise(resolve=>setTimeout(resolve,10));}assert.equal(waiting,true);
 await blocker.query('COMMIT');assert.equal((await reading).sourceAuthorization.grantId,grant.id);assert.equal((await withdrawing).state,'revoked');await assert.rejects(fixture.snapshot(),error=>error.status===403);
 }finally{await blocker.query('ROLLBACK');blocker.release();if(reading)await reading.catch(()=>{});if(withdrawing)await withdrawing.catch(()=>{});}
});
async function sourceFixture(){
 const actor={...await pimPrincipal('license-scope-administrator'),iss:issuer,client_id:'native-source-console'};const reader={...await pimPrincipal('license-scope-reader'),iss:issuer,client_id:'native-source-console'};const groupId=await group();await add(groupId,await identity());
 const state={revision:'1',enabled:true,canReadGroupSources:true,clientReads:0,checks:0,onClient:null,onCheck:null};
 const clients={issuer,get:async clientId=>{state.clientReads++;if(state.onClient)await state.onClient(state.clientReads);return{schemaVersion:1,clientId,revision:state.revision,enabled:state.enabled,canReadGroupSources:state.canReadGroupSources};}};
 const store=new(require('../GroupSourceGrants').GroupSourceGrants)(database,{clients,revalidate:async user=>{state.checks++;if(state.onCheck)await state.onCheck(state.checks,user);if(user.actor_type==='application'&&(!state.enabled||user.client_revision!==state.revision))throw Object.assign(new Error('Owned stale workload credential'),{status:401});}});
 const body={groupId,clientId:'native-dedicated-group-source',expectedClientRevision:'1',expiresAt:new Date(Date.now()+3600000).toISOString(),reason:'Explicit narrowly scoped group license source consent',acknowledgeReadScope:true};
 const workload={iss:issuer,sub:body.clientId,client_id:body.clientId,client_revision:'1',actor_type:'application',token_use:'access',scope:sourcePurpose,permissions:[sourcePurpose]};
 return{actor,reader,groupId,state,store,body,workload,create:()=>store.create(body,actor,'Bearer original-native-source-author'),snapshot:()=>store.snapshot(groupId,workload,'Bearer native-source-client')};
}
test('expiring source consent grants only an exact canonical group frame to the captured dedicated client generation',async()=>{
 const fixture=await sourceFixture();await assert.rejects(fixture.snapshot(),error=>error.status===403);const grant=await fixture.create();const snapshot=await fixture.snapshot();assert.equal(snapshot.schemaVersion,3);assert.equal(snapshot.viewerUserId,null);
 assert.deepEqual(snapshot.sourceAuthorization,{grantId:grant.id,version:'1',issuer,clientId:fixture.body.clientId,clientRevision:'1',expiresAt:grant.expiresAt});assert.equal(snapshot.memberIds.length,1);
 assert.equal((await fixture.store.list(fixture.groupId,fixture.reader,'Bearer original-native-source-reader')).grants[0].id,grant.id);await assert.rejects(fixture.store.snapshot(await group(),fixture.workload,'Bearer native-source-client'),error=>error.status===403);
});
test('source-consent administrators need an explicit existing protected duty and verified fresh factor evidence',async()=>{
 const fixture=await sourceFixture();for(const role of ['admin','license-manager','group-administrator']){const actor={...await pimPrincipal(role),iss:issuer,client_id:'native-console'};await assert.rejects(fixture.store.create(fixture.body,actor,'Bearer original'),error=>error.status===403);}
 await assert.rejects(fixture.store.create(fixture.body,{...fixture.actor,mfa_authorization:undefined},'Bearer original'),error=>error.status===428);
 await assert.rejects(fixture.store.create(fixture.body,fixture.reader,'Bearer original'),error=>error.status===403);
});
test('source consent never inherits an arbitrary issuer, human console client or non-dedicated OAuth registration',async()=>{
 const fixture=await sourceFixture();await assert.rejects(fixture.store.create({...fixture.body,clientId:fixture.actor.client_id},fixture.actor,'Bearer original'),error=>error.status===403);
 await assert.rejects(fixture.store.create(fixture.body,{...fixture.actor,iss:'https://other-issuer.test'},'Bearer original'),error=>error.status===403);
 fixture.state.canReadGroupSources=false;await assert.rejects(fixture.create(),error=>error.status===409);assert.equal((await database.query('SELECT count(*)::int AS count FROM identity_group_source_grants')).rows[0].count,0);
});
test('source consent rejects injected authority, invalid horizons and legacy identifiers without changing directory membership',async()=>{
 const fixture=await sourceFixture();for(const change of [{groupId:'legacy'},{expiresAt:new Date(Date.now()+31000).toISOString()},{expiresAt:new Date(Date.now()+2592001000).toISOString()},{clientRevision:'999'},{issuer:'forged'},{acknowledgeReadScope:false}])await assert.rejects(fixture.store.create({...fixture.body,...change},fixture.actor,'Bearer original'),error=>error.status===400);
 assert.equal((await database.query('SELECT count(*)::int AS count FROM group_members WHERE group_id=$1',[fixture.groupId])).rows[0].count,1);
});
test('conditional consent withdrawal retains evidence and cannot be revived or extended by editing a row',async()=>{
 const fixture=await sourceFixture();const grant=await fixture.create();const body={reason:'Explicit source read consent withdrawal',acknowledgeReadScope:true};await assert.rejects(fixture.store.revoke(grant.id,undefined,body,fixture.actor,'Bearer original'),error=>error.status===428);
 const revoked=await fixture.store.revoke(grant.id,`"od-group-source:${grant.id}:1"`,body,fixture.actor,'Bearer original');assert.equal(revoked.state,'revoked');assert.equal(revoked.version,'2');await assert.rejects(fixture.snapshot(),error=>error.status===403);
 await assert.rejects(fixture.store.revoke(grant.id,`"od-group-source:${grant.id}:1"`,body,fixture.actor,'Bearer original'),error=>error.status===412);
 for(const sql of ["UPDATE identity_group_source_grants SET expires_at=expires_at+interval '1 day'","DELETE FROM identity_group_source_grants","DELETE FROM identity_group_source_audit"])await assert.rejects(database.query(sql),error=>error.code==='42501');
 const replacement=await fixture.create();assert.notEqual(replacement.id,grant.id);assert.equal((await fixture.snapshot()).sourceAuthorization.grantId,replacement.id);
});
test('expiry closes source reads without a sweeper and reapplying migrations cannot stamp an old consent as new',async()=>{
 const fixture=await sourceFixture();const grant=await fixture.create();const before=(await database.query('SELECT * FROM identity_group_source_grants')).rows;await database.query(fs.readFileSync(path.join(__dirname,'../../migrations/021_group_source_consents.sql'),'utf8'));
 assert.deepEqual((await database.query('SELECT * FROM identity_group_source_grants')).rows,before);await database.query("CREATE OR REPLACE FUNCTION identity_group_source_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+interval '3601 seconds'; $$");
 await assert.rejects(fixture.snapshot(),error=>error.status===403);assert.equal((await fixture.store.get(grant.id,fixture.reader,'Bearer original-native-source-reader')).state,'expired');assert.equal((await database.query('SELECT count(*)::int AS count FROM identity_group_source_audit')).rows[0].count,1);
});
test('client disablement, re-enable or secret-generation changes cannot revalidate a saved source consent',async()=>{
 const fixture=await sourceFixture();const grant=await fixture.create();fixture.state.enabled=false;await assert.rejects(fixture.snapshot(),error=>error.status===401);fixture.state.enabled=true;fixture.state.revision='2';await assert.rejects(fixture.snapshot(),error=>error.status===401);
 fixture.workload.client_revision='2';await assert.rejects(fixture.snapshot(),error=>error.status===403);assert.equal((await fixture.store.get(grant.id,fixture.reader,'Bearer original-native-source-reader')).clientRevision,'1');
});
test('a client generation changed during consent audit DML rolls back both consent and immutable evidence',async()=>{
 const fixture=await sourceFixture();fixture.state.onClient=async count=>{if(count===2)fixture.state.revision='2';};await assert.rejects(fixture.create(),error=>error.status===409);
 assert.equal((await database.query('SELECT count(*)::int AS count FROM identity_group_source_grants')).rows[0].count,0);assert.equal((await database.query('SELECT count(*)::int AS count FROM identity_group_source_audit')).rows[0].count,0);
});
test('a source writer cannot silently consent to a client generation newer than the one explicitly confirmed',async()=>{
 const fixture=await sourceFixture();fixture.state.revision='2';await assert.rejects(fixture.create(),error=>error.status===412);assert.equal((await database.query('SELECT count(*)::int AS count FROM identity_group_source_grants')).rows[0].count,0);
});
test('original source administrator loss after consent DML cannot acknowledge a successful grant',async()=>{
 const fixture=await sourceFixture();fixture.state.onCheck=async count=>{if(count===3)throw Object.assign(new Error('Owned original consent author revoked'),{status:401});};await assert.rejects(fixture.create(),error=>error.status===401);assert.equal((await database.query('SELECT count(*)::int AS count FROM identity_group_source_grants')).rows[0].count,0);
});
test('a source writer disabled behind the actual group lock cannot use the earlier verified identity',async()=>{
 const fixture=await sourceFixture();const blocker=await database.pool.connect();let pending;
 try{await blocker.query('BEGIN');await blocker.query('SELECT id FROM groups WHERE id=$1 FOR UPDATE',[fixture.groupId]);pending=fixture.create();pending.catch(()=>{});let waiting=false;
 for(let attempt=0;attempt<200;attempt++){waiting=(await database.query("SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'SELECT id FROM groups WHERE id=%FOR UPDATE'")).rows.length>0;if(waiting)break;await new Promise(resolve=>setTimeout(resolve,10));}assert.equal(waiting,true);
 await database.write('UPDATE users SET enabled=false WHERE id=$1',[fixture.actor.userId],'owned-consent-author-disable');await blocker.query('COMMIT');await assert.rejects(pending,error=>error.status===401);
 assert.equal((await database.query('SELECT count(*)::int AS count FROM identity_group_source_grants')).rows[0].count,0);
 }finally{await blocker.query('ROLLBACK');blocker.release();if(pending)await pending.catch(()=>{});}
});
test('source consent audit loss rolls back configuration instead of creating an unaudited workload reader',async()=>{
 const fixture=await sourceFixture();await database.query('ALTER TABLE identity_group_source_audit RENAME TO held_source_audit');try{await assert.rejects(fixture.create());}finally{await database.query('ALTER TABLE held_source_audit RENAME TO identity_group_source_audit');}
 assert.equal((await database.query('SELECT count(*)::int AS count FROM identity_group_source_grants')).rows[0].count,0);
});
test('source authorization expiring during the final live check cannot commit and its known deadline cannot produce a snapshot',async()=>{
 await administration.query('CREATE TABLE '+clockSchema+'.source_clock(offset_seconds integer NOT NULL);INSERT INTO '+clockSchema+'.source_clock VALUES(0)');await database.query("CREATE OR REPLACE FUNCTION identity_group_source_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+offset_seconds*interval '1 second' FROM "+clockSchema+".source_clock; $$");
 const fixture=await sourceFixture();fixture.state.onCheck=async count=>{if(count===3)await administration.query('UPDATE '+clockSchema+'.source_clock SET offset_seconds=3601');};
 try{await assert.rejects(fixture.create(),error=>error.status===409||error.code==='23514');assert.equal((await database.query('SELECT count(*)::int AS count FROM identity_group_source_grants')).rows[0].count,0);}finally{await database.query('CREATE OR REPLACE FUNCTION identity_group_source_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp(); $$');await administration.query('DROP TABLE '+clockSchema+'.source_clock');}
});
test('concurrent source consent writers have one exact current consent and one audited winner',async()=>{
 const fixture=await sourceFixture();const results=await Promise.allSettled([fixture.create(),fixture.create()]);assert.equal(results.filter(value=>value.status==='fulfilled').length,1);assert.equal((await database.query('SELECT count(*)::int AS count FROM identity_group_source_grants')).rows[0].count,1);assert.equal((await database.query('SELECT count(*)::int AS count FROM identity_group_source_audit')).rows[0].count,1);
});
test('an application source cannot borrow human roles, widened scopes or another client incarnation to read group members',async()=>{
 const fixture=await sourceFixture();await fixture.create();for(const change of [{actor_type:'user'},{client_id:'another-client'},{client_revision:'0'},{scope:sourcePurpose+' licenses.users.read'},{roles:['admin']},{permissions:['licenses.groups.read']},{identity_authorization:fixture.actor.identity_authorization}])await assert.rejects(fixture.store.snapshot(fixture.groupId,{...fixture.workload,...change},'Bearer source'),error=>error.status===403);
});
test('raw consent DML cannot substitute an unprivileged canonical user even with a fresh-looking JSON proof',async()=>{
 const fixture=await sourceFixture();const person={...await pimPrincipal(),iss:issuer,client_id:'native-console'};await assert.rejects(database.transaction(async client=>{await fixture.store.context(client,person,'create','Unprivileged consent forgery refused',{schemaVersion:1,clientId:fixture.body.clientId,revision:'1',enabled:true,canReadGroupSources:true});await client.query('INSERT INTO identity_group_source_grants(group_id,issuer,client_id,client_revision,created_by,expires_at) VALUES($1,$2,$3,1,$4,$5)',[fixture.groupId,issuer,fixture.body.clientId,person.userId,fixture.body.expiresAt]);}),error=>error.code==='42501');
});
test('group schema v2 exports the canonical incarnation and eligibility generation with a bounded coherent observation',async()=>{
 const userId=await identity();const groupId=await group();await add(groupId,userId);const first=await snapshots.snapshot(groupId);const again=await snapshots.snapshot(groupId);
 const membership=(await database.query('SELECT membership_id FROM group_members WHERE group_id=$1',[groupId])).rows[0];const user=(await database.query('SELECT eligibility_revision FROM users WHERE id=$1',[userId])).rows[0];
 assert.equal(first.schemaVersion,3);assert.equal(first.sourceAuthorization,null);assert.equal(Date.parse(first.validUntil)-Date.parse(first.observedAt),300000);assert.equal(first.revision,again.revision);assert.ok(Date.parse(again.observedAt)>=Date.parse(first.observedAt));
 assert.deepEqual(first.memberships,[{userId,membershipId:membership.membership_id,eligibilityRevision:user.eligibility_revision,reviewDeadlineAt:null}]);
 await database.write('DELETE FROM group_members WHERE group_id=$1 AND user_id=$2',[groupId,userId],'owned-lease-reissue');await add(groupId,userId);
 const reissued=await snapshots.snapshot(groupId);assert.notEqual(reissued.memberships[0].membershipId,first.memberships[0].membershipId);assert.notEqual(reissued.revision,first.revision);
});
test('group v2 proof carries the actual independent membership review deadline and never reports an awaiting edge as active',async()=>{
 const fixture=await membershipFixture(false);assert.equal((await groupApi('POST','/api/groups/'+fixture.groupId+'/members',fixture.creator,{userId:fixture.owner.userId})).status,200);const waiting=await snapshots.snapshot(fixture.groupId);assert.deepEqual(waiting.memberIds,[]);assert.deepEqual(waiting.memberships,[]);
 const row=(await membershipRows(fixture))[0];const retained=await membershipDecision(fixture,row);assert.equal(retained.status,200);const active=await snapshots.snapshot(fixture.groupId);
 assert.equal(active.memberships[0].membershipId,row.membershipId);assert.equal(active.memberships[0].reviewDeadlineAt,retained.body.deadlineAt);assert.ok(Date.parse(active.memberships[0].reviewDeadlineAt)>Date.parse(active.observedAt));
});

test('role assurance catalog has an immutable security-management minimum and migration reapplication preserves versions', async () => {
  const roles = require('../../../../../packages/directory-role-contract').ROLES;
  const catalog = (await database.query('SELECT role FROM identity_role_authentication ORDER BY role COLLATE "C"')).rows.map(row => row.role);
  assert.deepEqual(catalog,[...roles].sort());
  const before = (await database.query("SELECT * FROM identity_role_authentication WHERE role='authentication-policy-administrator'")).rows[0];
  assert.equal(before.mfa_required,true); assert.equal(before.max_age_seconds,300);
  await assert.rejects(database.write("UPDATE identity_role_authentication SET version=version+1,mfa_required=false WHERE role=$1",[before.role],'fixture'));
  await assert.rejects(database.query('DELETE FROM identity_role_authentication WHERE role=$1',[before.role]));
  await database.query(fs.readFileSync(path.join(__dirname,'../../migrations/010_role_authentication.sql'),'utf8'));
  assert.deepEqual((await database.query('SELECT * FROM identity_role_authentication WHERE role=$1',[before.role])).rows[0],before);
});
test('actual role-policy API separates duties, requires fresh canonical MFA and commits actor/reason with the exact next version', async () => {
  const manager = await pimPrincipal('authentication-policy-administrator'); const reader = await pimPrincipal('authentication-policy-reader'); const roleAdmin = await pimPrincipal('role-administrator');
  const path = '/api/identity/authentication/roles/license-reader';
  const before = await api('GET',path,reader); assert.equal(before.status,200); assert.equal(Object.keys(before.body).length,8);
  const input = { required:true,maxAgeSeconds:300,reason:'Reviewed canonical license read assurance' };
  const headers = { 'If-Match':policyEtag(before.body.role,before.body.version) };
  assert.equal((await api('GET','/api/users',manager)).status,403);
  for (const denied of [reader,roleAdmin]) assert.equal((await api('PUT',path,denied,input,headers)).status,403);
  assert.equal((await api('PUT',path,{ ...manager,mfa_authorization:undefined },input,headers)).body.error,'fresh_mfa_required');
  const saved = await api('PUT',path,manager,input,headers); assert.equal(saved.status,200); assert.equal(saved.body.version,String(BigInt(before.body.version)+1n));
  assert.equal((await api('PUT',path,manager,input,headers)).status,412);
  const audit = (await database.query('SELECT * FROM identity_role_authentication_audit WHERE role=$1 ORDER BY created_at DESC LIMIT 1',[before.body.role])).rows[0];
  assert.equal(JSON.parse(audit.actor).userId,manager.userId); assert.equal(audit.reason,input.reason); assert.equal(audit.current.mfa_required,true);
  for (const operation of ['UPDATE identity_role_authentication_audit SET reason=reason','DELETE FROM identity_role_authentication_audit']) await assert.rejects(database.query(operation+' WHERE id=$1',[audit.id]));
});
test('row-locked role-policy races admit one exact version and policy off/on cannot resurrect a canonical role fingerprint', async () => {
  const manager = { ...await pimPrincipal('authentication-policy-administrator'),iss:issuer }; const owner = await pimPrincipal('compliance-reader');
  const store = new RoleAuthentication(database, { revalidate: async () => {} }); const source = new AuthorizationState(database); const first = await source.state(issuer,owner.sub);
  const before = await store.get('compliance-reader',manager); const input = { required:true,maxAgeSeconds:900,reason:'Reviewed role assurance race evidence' };
  const settled = await Promise.allSettled([store.change(before.role,policyEtag(before.role,before.version),input,manager),store.change(before.role,policyEtag(before.role,before.version),input,manager)]);
  assert.equal(settled.filter(result=>result.status==='fulfilled').length,1); assert.equal(settled.find(result=>result.status==='rejected').reason.status,412);
  const required = await source.state(issuer,owner.sub); assert.deepEqual(required.authentication,{ required:true,maxAgeSeconds:900 }); assert.notEqual(required.context.rolesRevision,first.context.rolesRevision);
  const configured = (await database.query('SELECT * FROM identity_role_authentication WHERE role=$1',[before.role])).rows[0];
  await database.query(fs.readFileSync(path.join(__dirname,'../../migrations/010_role_authentication.sql'),'utf8'));
  assert.deepEqual((await database.query('SELECT * FROM identity_role_authentication WHERE role=$1',[before.role])).rows[0],configured);
  const current = await store.get(before.role,manager); await store.change(before.role,policyEtag(before.role,current.version),{ ...input,required:false },manager);
  const relaxed = await source.state(issuer,owner.sub); assert.equal(relaxed.authentication.required,false); assert.notEqual(relaxed.context.rolesRevision,first.context.rolesRevision); assert.notEqual(relaxed.context.rolesRevision,required.context.rolesRevision);
});
test('role-policy audit loss rolls back configuration and current actor revocation is rechecked after the policy lock', async () => {
  const manager = { ...await pimPrincipal('authentication-policy-administrator'),iss:issuer }; const store = new RoleAuthentication(database, { revalidate: async () => {} }); const role = 'operations-reader';
  const before = await store.get(role,manager); const input = { required:true,maxAgeSeconds:300,reason:'Reviewed atomic policy source mutation' };
  await database.query('ALTER TABLE identity_role_authentication_audit RENAME TO withheld_authentication_audit');
  try { await assert.rejects(store.change(role,policyEtag(role,before.version),input,manager)); }
  finally { await database.query('ALTER TABLE withheld_authentication_audit RENAME TO identity_role_authentication_audit'); }
  assert.equal((await store.get(role,manager)).version,before.version);
  const blocker = await database.pool.connect(); let pending;
  try {
    await blocker.query('BEGIN'); await blocker.query('SELECT role FROM identity_role_authentication WHERE role=$1 FOR UPDATE',[role]);
    pending = store.change(role,policyEtag(role,before.version),input,manager); pending.catch(()=>{});
    let waiting = false; const deadline = Date.now()+2000;
    while (Date.now()<deadline) {
      waiting = (await database.query("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%identity_role_authentication%FOR UPDATE%') AS waiting")).rows[0].waiting;
      if (waiting) break;
      await new Promise(resolve=>setTimeout(resolve,10));
    }
    assert.equal(waiting,true);
    await database.write('UPDATE users SET authorization_revision=authorization_revision+1 WHERE id=$1',[manager.userId],'independent-security-reset');
    await blocker.query('COMMIT'); await assert.rejects(pending,error=>error.status===401);
  } finally { await blocker.query('ROLLBACK'); blocker.release(); if (pending) await pending.catch(()=>{}); }
  assert.equal((await store.get(role,manager)).version,before.version);
});

test('membership incarnations are immutable and survive migration reapplication, never remove/readd', async () => {
  const userId = await identity(); const groupId = await group(); await add(groupId,userId);
  const first = (await database.query('SELECT membership_id FROM group_members WHERE group_id=$1 AND user_id=$2',[groupId,userId])).rows[0].membership_id;
  await assert.rejects(database.query('UPDATE group_members SET membership_id=gen_random_uuid() WHERE group_id=$1',[groupId]));
  await database.query(fs.readFileSync(path.join(__dirname,'../../migrations/009_application_memberships.sql'),'utf8'));
  assert.equal((await database.query('SELECT membership_id FROM group_members WHERE group_id=$1',[groupId])).rows[0].membership_id,first);
  await database.query(fs.readFileSync(path.join(__dirname,'../../migrations/028_directory_group_mutations.sql'),'utf8'));for(const file of ['051_company_group_rule_automation.sql','052_live_company_group_rules.sql','053_company_automation_changes.sql'])await database.query(fs.readFileSync(path.join(__dirname,'../../migrations',file),'utf8'));
  await database.write('DELETE FROM group_members WHERE group_id=$1 AND user_id=$2',[groupId,userId],'membership-operator'); await add(groupId,userId);
  assert.notEqual((await database.query('SELECT membership_id FROM group_members WHERE group_id=$1',[groupId])).rows[0].membership_id,first);
});
test('canonical membership authority is an exact repeatable snapshot, not submitted group names or aliases', async () => {
  const userId = await identity(); const groupId = await group(); await add(groupId,userId);
  await database.write('INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES($1,$2,$3)',[issuer,'application-snapshot',userId],'fixture-link');
  const source = new AuthorizationState(database); const first = await source.state(issuer,'application-snapshot');
  assert.equal(first.schemaVersion,6); assert.equal(first.memberships.length,1); assert.equal(first.memberships[0].groupId,groupId);
  assert.equal((await source.target('group',groupId,userId)).actorIsMember,true);
  assert.deepEqual(Object.keys(await source.target('user',userId,userId)).sort(),['active','actorIsMember','revision','schemaVersion','targetId','targetType']);
  await database.write('DELETE FROM group_members WHERE group_id=$1 AND user_id=$2',[groupId,userId],'membership-operator');
  assert.deepEqual((await source.state(issuer,'application-snapshot')).memberships,[]);
});
test('a membership removed between canonical identity and membership reads cannot produce a mixed authority snapshot', async () => {
  const userId = await identity(); const groupId = await group(); await add(groupId,userId);
  await database.write('INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES($1,$2,$3)',[issuer,'repeatable-application',userId],'fixture-link');
  const incarnation = (await database.query('SELECT membership_id FROM group_members WHERE group_id=$1',[groupId])).rows[0].membership_id;
  let removed = false;
  const overlapping = new AuthorizationState({ transaction: (operation,options) => database.transaction(client => operation({ query: async (sql,parameters) => {
    const result = await client.query(sql,parameters);
    if (!removed && sql.includes('JOIN users ON users.id=identity_subject_links.user_id')) {
      removed = true; await database.write('DELETE FROM group_members WHERE group_id=$1 AND user_id=$2',[groupId,userId],'concurrent-membership-operator');
    }
    return result;
  } }),options) });
  const snapshot = await overlapping.state(issuer,'repeatable-application');
  assert.equal(removed,true); assert.deepEqual(snapshot.memberships,[{ groupId,membershipId: incarnation }]);
  assert.deepEqual((await new AuthorizationState(database).state(issuer,'repeatable-application')).memberships,[]);
});

before(async () => {
  await administration.query(`CREATE SCHEMA ${schema}`);await administration.query('CREATE SCHEMA '+clockSchema);
  const url = new URL(process.env.IDENTITY_TEST_DATABASE_URL);
  url.searchParams.set('options', `-c search_path=${schema},public`);
  process.env.DATABASE_URL = url.toString();
  process.env.OIDC_ISSUER = issuer;
  const keys = await generateKeyPair('RS256');
  privateKey = keys.privateKey;
  const publicKey = { ...await exportJWK(keys.publicKey), kid: 'identity-tests', alg: 'RS256', use: 'sig' };
  jwks = http.createServer(async (request, response) => {
    response.setHeader('Content-Type', 'application/json');
    if (['/oauth/access-state','/oauth/tenant-state'].includes(request.url)) {
      try {
        const { payload } = await require('jose').jwtVerify(request.headers.authorization.slice(7), keys.publicKey, { issuer, audience: 'opendirectory-api' });
        if (request.url === '/oauth/tenant-state') {
          const state = await new AuthorizationState(database).state(issuer,payload.sub);
          if (!state.active || !require('../../../../../packages/identity-authorization-contract').sameContext(state.context,payload.identity_authorization)) return response.end(JSON.stringify({ schemaVersion:1,active:false }));
          return response.end(JSON.stringify({ schemaVersion:1,active:true,issuer,subject:payload.sub,tokenId:payload.jti,expiresAt:payload.exp,context:state.context,tenant:state.tenant }));
        }
        return response.end(JSON.stringify({ schemaVersion: 1, active: true, issuer: payload.iss, subject: payload.sub, tokenId: payload.jti, expiresAt: payload.exp }));
      } catch { response.statusCode = 401; return response.end('{}'); }
    }
    response.end(JSON.stringify({ keys: [publicKey] }));
  });
  await new Promise(resolve => jwks.listen(0, '127.0.0.1', resolve));
  process.env.JWKS_URI = `http://127.0.0.1:${jwks.address().port}/jwks`;
  process.env.OIDC_ACCESS_STATE_URL = `http://127.0.0.1:${jwks.address().port}/oauth/access-state`;
  process.env.OIDC_TENANT_STATE_URL = `http://127.0.0.1:${jwks.address().port}/oauth/tenant-state`;
  database = require('../db');
  assert.equal(await database.initDb(), true);
  await require('../../../../../scripts/lib/tenant-ownership-fixture.cjs').installTenantFixture(database,schema);
  snapshots = new GroupSnapshotStore(database);
  server = require('../index').listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
});

beforeEach(async () => {
  await database.query('TRUNCATE identity_tenant_retirements,identity_tenant_ownership,identity_tenant_events,identity_tenant_outbox CASCADE');
  await database.query('TRUNCATE identity_group_source_audit,identity_group_source_grants CASCADE');
  await database.query('CREATE OR REPLACE FUNCTION identity_group_source_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp(); $$');
  await database.query('TRUNCATE identity_membership_review_audit,identity_membership_review_leases,identity_membership_review_policies,identity_membership_origins CASCADE');
  await database.query('CREATE OR REPLACE FUNCTION identity_membership_review_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp(); $$');
  await database.query('TRUNCATE identity_role_review_audit,identity_role_review_leases,identity_role_review_policies CASCADE');
  await database.query('CREATE OR REPLACE FUNCTION identity_role_review_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp(); $$');
  await database.query('TRUNCATE group_members, users, groups, ous, identity_deleted_groups, identity_group_audit, identity_group_outbox,identity_user_audit,identity_user_outbox,identity_deleted_users CASCADE');
});

after(async () => {
  for (const listener of [server, jwks]) {
    if (listener) { listener.closeAllConnections(); await new Promise(resolve => listener.close(resolve)); }
  }
  if (database) await database.pool.end();
  await administration.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);await administration.query('DROP SCHEMA IF EXISTS '+clockSchema+' CASCADE');
  await administration.end();
});

async function identity() {
  const id = randomUUID();
  await database.write('INSERT INTO users(id,username,email) VALUES($1,$2,$3)', [id, id, `${id}@test.invalid`], 'test-administrator');
  return id;
}

async function group() {
  const id = randomUUID();
  await database.write('INSERT INTO groups(id,name) VALUES($1,$2)', [id, 'Engineering'], 'test-administrator');
  return id;
}

async function add(groupId, userId) {
  await database.write('INSERT INTO group_members(group_id,user_id) VALUES($1,$2) ON CONFLICT DO NOTHING', [groupId, userId], 'membership-operator');
}

async function groupApi(method,route,claims={},body,headers={}){
 const identity=/^\/api\/groups\/([a-f0-9-]{36})(?:\/|$)/i.exec(route)?.[1];
 const row=identity?(await database.query('SELECT revision FROM groups WHERE id=$1',[identity])).rows[0]:null;
 return api(method,route,claims,body,{...(identity?{'If-Match':`"group-${identity}-${row?.revision||'1'}"`}:{}),...headers});
}
async function api(method, route, claims = {}, body, headers = {}) {
  const readPermission = /\/roles(?:\?|$)/.test(route) ? 'identities.roles.read' : route.startsWith('/api/users') ? 'users.read' : route.startsWith('/api/groups') ? 'groups.read' : route.startsWith('/api/ous') ? 'ous.read' : null;
  const creationPermission = method==='POST' ? {'/api/users':'users.create','/api/groups':'groups.create','/api/ous':'ous.create'}[route] : null;
  const userMutationPermission = /^\/api\/users\/[a-f0-9-]{36}(?:\?|$)/i.test(route) ? ({PUT:'users.update',DELETE:'users.delete'})[method] : method==='POST' && /^\/api\/users\/[a-f0-9-]{36}\/authorization\/invalidate(?:\?|$)/i.test(route) ? 'users.sessions.invalidate' : null;
  const groupMutationPermission=/^\/api\/groups\/[a-f0-9-]{36}(?:\/members(?:\/[a-f0-9-]{36})?)?(?:\?|$)/i.test(route)?route.includes('/members')&&['POST','DELETE'].includes(method)?'groups.members.manage':({PUT:'groups.update',DELETE:'groups.delete'})[method]:null;
  const directoryPermission = method==='GET' ? readPermission : creationPermission || userMutationPermission || groupMutationPermission;
  if (directoryPermission && require('../middleware/identityAccess').getIdentityPermissions(claims).includes(directoryPermission)
    && !require('../../../../../packages/identity-authorization-contract').validContext(claims.identity_authorization)) {
    let source = await new AuthorizationState(database).state(issuer,'native-directory-reader');
    if (!source.active) {
      const operator = await identity();
      await database.write('INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES($1,$2,$3)',[issuer,'native-directory-reader',operator],'Explicit native directory reader fixture');
      await database.write("INSERT INTO identity_role_assignments(user_id,role,reason) VALUES($1,'admin','Explicit native directory read authority fixture')",[operator],'Explicit native directory reader fixture');
      source = await new AuthorizationState(database).state(issuer,'native-directory-reader');
    }
    claims = {...claims,sub:'native-directory-reader',actor_type:'user',identity_authorization:source.context};
  }
  if (route === '/api/identity/links' && claims.roles?.includes('admin')) {
    let source = await new AuthorizationState(database).state(issuer,'native-link-operator');
    if (!source.active) {
      const operator = await identity();
      await database.write('INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES($1,$2,$3)',[issuer,'native-link-operator',operator],'Explicit native link administrator bootstrap');
      await database.write("INSERT INTO identity_role_assignments(user_id,role,reason) VALUES($1,'admin','Explicit native subject-link administration fixture')",[operator],'Explicit native link administrator bootstrap');
      source = await new AuthorizationState(database).state(issuer,'native-link-operator');
    }
    claims = { ...claims,sub:'native-link-operator',actor_type:'user',identity_authorization:source.context };
  }
  const token = await new SignJWT({ sub: 'verified-operator', jti: randomUUID(), token_use: 'access', ...claims }).setProtectedHeader({ alg: 'RS256', kid: 'identity-tests' })
    .setIssuer(issuer).setAudience('opendirectory-api').setIssuedAt().setExpirationTime('5m').sign(privateKey);
  const response = await fetch(`${base}${route}`, { method, headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', ...headers }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  return { status: response.status, headers: response.headers, body: response.status === 204 ? null : await response.json() };
}

test('self-binding is available without directory-read privileges and cannot select a different subject', async () => {
  const userId = await identity(); const other = await identity();
  const linked = { issuer, subject: 'verified-operator', userId };
  const missing = await api('GET', '/api/identity/subject?subject=someone-else', { directory_user_id: other });
  assert.equal(missing.status, 200); assert.deepEqual(missing.body, { schemaVersion: 1, issuer, subject: 'verified-operator', userId: null, enabled: null });
  assert.equal((await api('POST', '/api/identity/links', { roles: ['admin'] }, linked)).status, 201);
  const resolved = await api('GET', '/api/identity/subject?subject=someone-else&userId=forged', { directory_user_id: other, issuer: 'forged' });
  assert.equal(resolved.status, 200); assert.deepEqual(resolved.body, { schemaVersion: 1, issuer, subject: 'verified-operator', userId, enabled: true });
  assert.equal(resolved.headers.get('cache-control'), 'no-store');
  assert.equal((await api('GET', '/api/users')).status, 403);
  const stranger = await api('GET', '/api/identity/subject', { sub: 'someone-else', roles: ['admin'], directory_user_id: userId });
  assert.equal(stranger.body.userId, null);
});

test('self-binding exposes disablement and unlinking instead of returning a usable demo identity', async () => {
  const userId = await identity(); const body = { issuer, subject: 'verified-operator', userId };
  assert.equal((await api('POST', '/api/identity/links', { roles: ['admin'] }, body)).status, 201);
  await database.write('UPDATE users SET enabled=false WHERE id=$1', [userId], 'status-administrator');
  const inactive = await api('GET', '/api/identity/subject');
  assert.equal(inactive.body.userId, userId); assert.equal(inactive.body.enabled, false);
  assert.equal((await api('DELETE', '/api/identity/links', { roles: ['admin'] }, { issuer,subject:body.subject })).status, 204);
  const unlinked = await api('GET', '/api/identity/subject');
  assert.equal(unlinked.body.userId, null); assert.equal(unlinked.body.enabled, null);
});

test('eligibility snapshots are self-only unless a narrow read permission is actually granted', async () => {
  const userId = await identity(); const other = await identity();
  await database.write('INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES($1,$2,$3)', [issuer, 'verified-operator', userId], 'link-administrator');
  const self = await pimRefresh({ sub: 'verified-operator' });
  const own = await api('GET', `/api/license-users/${userId}/snapshot`, self);
  assert.equal(own.status, 200); assert.equal(own.body.userId, userId); assert.equal(own.body.enabled, true);
  assert.equal(own.headers.get('cache-control'), 'no-store');
  assert.deepEqual(Object.keys(own.body).sort(), ['deleted', 'enabled', 'revision', 'schemaVersion', 'userId']);
  assert.equal((await api('GET', `/api/license-users/${other}/snapshot`, { ...self, directory_user_id: other, scope: 'licenses.users.read' })).status, 403);
  assert.equal((await api('GET', `/api/license-users/${other}/snapshot`, await pimPrincipal('license-group-reader'))).status, 403);
  assert.equal((await api('GET', `/api/license-users/${other}/snapshot`, { ...self, permissions: ['licenses.users.read'] })).status, 403, 'A signed permission claim cannot replace the actual canonical user-source duty');
  for (const role of ['license-manager', 'license-approver', 'license-eligibility-reader']) {
    const claims = await pimPrincipal(role);
    assert.equal((await api('GET', `/api/license-users/${other}/snapshot`, claims)).status, 200);
    assert.equal((await api('GET', '/api/users', claims)).status, 403);
    assert.equal((await api('PUT', `/api/users/${other}`, claims, { enabled: false })).status, 403);
  }
});

test('eligibility versions advance only on state changes, cannot be forged, and survive migration reapplication', async () => {
  const userId = await identity(); const claims = await pimPrincipal('license-eligibility-reader');
  const read = async () => { const result = await api('GET', `/api/license-users/${userId}/snapshot`, claims); assert.equal(result.status, 200, JSON.stringify(result.body)); return result.body; };
  const original = await read();
  await database.write('UPDATE users SET title=$2,eligibility_revision=1 WHERE id=$1', [userId, 'New title'], 'metadata-editor');
  assert.deepEqual(await read(), original);
  await database.write('UPDATE users SET enabled=false WHERE id=$1', [userId], 'status-operator');
  const disabled = await read(); assert.equal(disabled.enabled, false); assert.ok(BigInt(disabled.revision) > BigInt(original.revision));
  await database.write('UPDATE users SET enabled=false WHERE id=$1', [userId], 'retry-operator');
  assert.deepEqual(await read(), disabled);
  await database.query(fs.readFileSync(path.join(__dirname, '../../migrations/004_user_eligibility.sql'), 'utf8'));
  assert.deepEqual(await read(), disabled);
  await database.write('UPDATE users SET enabled=true WHERE id=$1', [userId], 'status-operator');
  assert.ok(BigInt((await read()).revision) > BigInt(disabled.revision));
  await assert.rejects(database.query('UPDATE users SET id=$2 WHERE id=$1', [userId, randomUUID()]), error => error.code === '42501');
});

test('deletion has a durable newer tombstone, prevents UUID reuse, and is not confused with an unknown user', async () => {
  const userId = await identity(); const claims = await pimPrincipal('license-eligibility-reader');
  const original = await api('GET', `/api/license-users/${userId}/snapshot`, claims);
  assert.equal(original.status, 200, JSON.stringify(original.body));
  await database.write('DELETE FROM users WHERE id=$1', [userId], 'leaver-operator');
  const deleted = await api('GET', `/api/license-users/${userId}/snapshot`, claims);
  assert.equal(deleted.status, 200); assert.equal(deleted.body.deleted, true); assert.equal(deleted.body.enabled, false);
  assert.ok(BigInt(deleted.body.revision) > BigInt(original.body.revision));
  assert.equal((await api('GET', `/api/license-users/${randomUUID()}/snapshot`, claims)).status, 404);
  await assert.rejects(database.query('INSERT INTO users(id,username,email) VALUES($1,$2,$3)', [userId, 'reused', 'reused@test.invalid']), error => error.code === '23514');
  await assert.rejects(database.query('DELETE FROM identity_deleted_users WHERE user_id=$1', [userId]), error => error.code === '42501');
  const evidence = (await database.query('SELECT actor,details FROM identity_user_audit WHERE user_id=$1 ORDER BY revision DESC LIMIT 1', [userId])).rows[0];
  assert.equal(evidence.actor, 'leaver-operator'); assert.equal(evidence.details.deleted, true);
  await assert.rejects(database.query('UPDATE identity_user_audit SET actor=$1 WHERE user_id=$2', ['forged', userId]), error => error.code === '42501');
});

test('eligibility audit/outbox failures roll back user status and associated group revisions together', async () => {
  const userId = await identity(); const groupId = await group(); await add(groupId, userId);
  const original = await snapshots.snapshot(groupId);
  for (const table of ['identity_user_audit', 'identity_user_outbox']) {
    await database.query(`CREATE FUNCTION fail_user_evidence() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'user evidence unavailable'; END; $$ LANGUAGE plpgsql;
      CREATE TRIGGER injected_user_evidence BEFORE INSERT ON ${table} FOR EACH ROW EXECUTE FUNCTION fail_user_evidence()`);
    try {
      await assert.rejects(database.write('UPDATE users SET enabled=false WHERE id=$1', [userId], 'status-operator'));
      assert.equal((await database.query('SELECT enabled FROM users WHERE id=$1', [userId])).rows[0].enabled, true);
      assert.deepEqual(snapshotContent(await snapshots.snapshot(groupId)),snapshotContent(original));
    } finally { await database.query(`DROP TRIGGER injected_user_evidence ON ${table}; DROP FUNCTION fail_user_evidence()`); }
  }
});

test('legacy users acquire stable current eligibility revisions without fabricated historical evidence', async () => {
  const schema = `legacy_users_${randomUUID().replaceAll('-', '')}`;
  await administration.query(`CREATE SCHEMA ${schema}`);
  const legacy = new Pool({ connectionString: process.env.IDENTITY_TEST_DATABASE_URL, max: 1, options: `-c search_path=${schema},public` });
  try {
    await legacy.query(fs.readFileSync(path.join(__dirname, '../../migrations/001_identity_schema.sql'), 'utf8'));
    const userId = randomUUID(); await legacy.query('INSERT INTO users(id,username,email,enabled) VALUES($1,$2,$3,false)', [userId, 'old-user', 'old@test.invalid']);
    const migration = fs.readFileSync(path.join(__dirname, '../../migrations/004_user_eligibility.sql'), 'utf8');
    await legacy.query(migration);
    const original = (await legacy.query('SELECT eligibility_revision,enabled FROM users WHERE id=$1', [userId])).rows[0];
    assert.ok(BigInt(original.eligibility_revision) > 0n); assert.equal(original.enabled, false);
    await legacy.query(migration);
    assert.deepEqual((await legacy.query('SELECT eligibility_revision,enabled FROM users WHERE id=$1', [userId])).rows[0], original);
    assert.equal((await legacy.query('SELECT COUNT(*)::int AS count FROM identity_user_audit')).rows[0].count, 0);
  } finally { await legacy.end(); await administration.query(`DROP SCHEMA ${schema} CASCADE`); }
});

test('group snapshots expose canonical enabled member IDs, inactive accounts, and a durable revision', async () => {
  const groupId = await group();
  const active = await identity();
  const inactive = await identity();
  await add(groupId, active); await add(groupId, inactive);
  await database.write('UPDATE users SET enabled=false WHERE id=$1', [inactive], 'offboarding-operator');
  const snapshot = await snapshots.snapshot(groupId);
  assert.deepEqual(snapshot.memberIds, [active]);
  assert.deepEqual(snapshot.inactiveMemberIds, [inactive]);
  assert.deepEqual(snapshot.unresolvedMemberIds, []);
  assert.match(snapshot.revision, /^\d+$/);
});

test('concurrent inserts preserve every member and retries do not advance unchanged membership revisions', async () => {
  const groupId = await group();
  const users = await Promise.all(Array.from({ length: 12 }, identity));
  const changes = await Promise.allSettled(users.map(userId => add(groupId, userId)));
  assert.ok(changes.every(change => change.status === 'fulfilled'));
  const first = await snapshots.snapshot(groupId);
  assert.deepEqual([...first.memberIds].sort(), [...users].sort());
  await add(groupId, users[0]);
  assert.equal((await snapshots.snapshot(groupId)).revision, first.revision);
});

test('membership removal, disabling, and reactivation advance the group revision', async () => {
  const groupId = await group(); const userId = await identity();
  await add(groupId, userId);
  let previous = await snapshots.snapshot(groupId);
  for (const enabled of [false, true]) {
    await database.write('UPDATE users SET enabled=$2 WHERE id=$1', [userId, enabled], 'status-operator');
    const current = await snapshots.snapshot(groupId);
    assert.ok(BigInt(current.revision) > BigInt(previous.revision));
    assert.equal(current.memberIds.includes(userId), enabled);
    previous = current;
  }
  await database.write('DELETE FROM group_members WHERE group_id=$1 AND user_id=$2', [groupId, userId], 'membership-operator');
  const current = await snapshots.snapshot(groupId);
  assert.ok(BigInt(current.revision) > BigInt(previous.revision));
  assert.deepEqual(current.memberIds, []);
});

test('a deleted user releases membership in every group without leaving dangling beneficiaries', async () => {
  const userId = await identity();
  const groups = await Promise.all([group(), group()]);
  for (const groupId of groups) await add(groupId, userId);
  await database.write('DELETE FROM users WHERE id=$1', [userId], 'offboarding-operator');
  for (const groupId of groups) assert.deepEqual((await snapshots.snapshot(groupId)).memberIds, []);
  assert.equal((await database.query('SELECT COUNT(*)::int AS count FROM group_members')).rows[0].count, 0);
});

test('membership insertion racing with user deletion cannot leave an orphaned beneficiary', async () => {
  for (let attempt = 0; attempt < 6; attempt++) {
    const groupId = await group(); const userId = await identity();
    const outcomes = await Promise.allSettled([add(groupId, userId), database.write('DELETE FROM users WHERE id=$1', [userId], 'offboarding-operator')]);
    assert.equal(outcomes[1].status, 'fulfilled');
    if (outcomes[0].status === 'rejected') assert.equal(outcomes[0].reason.code, '23503');
    assert.deepEqual((await snapshots.snapshot(groupId)).memberIds, []);
    assert.equal((await database.query('SELECT COUNT(*)::int AS count FROM group_members WHERE user_id=$1', [userId])).rows[0].count, 0);
  }
});

test('snapshots remain consistent when membership changes after the revision was read', async () => {
  const groupId = await group(); const userId = await identity();
  const original = await snapshots.snapshot(groupId);
  let pending;let waiting=false;
  const racing = new GroupSnapshotStore({ transaction: (operation, options) => database.transaction(async client => operation({
    query: async (sql, params) => {
      const result = await client.query(sql, params);
      if (sql.startsWith('SELECT id, name, revision')) {
        pending=add(groupId,userId);pending.catch(()=>{});
        for(let attempt=0;attempt<200;attempt++){waiting=(await database.query("SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'INSERT INTO group_members(group_id,user_id)%'")).rows.length>0;if(waiting)break;await new Promise(resolve=>setTimeout(resolve,10));}
      }
      return result;
    },
  }), options) });
  const beforeChange = await racing.snapshot(groupId);
  assert.equal(beforeChange.revision, original.revision);
  assert.deepEqual(beforeChange.memberIds, []);
  assert.equal(waiting,true);await pending;
  assert.deepEqual((await snapshots.snapshot(groupId)).memberIds, [userId]);
});

test('deletion produces a newer durable tombstone and cannot be undone by reusing its identifier', async () => {
  const groupId = await group(); const original = await snapshots.snapshot(groupId);
  await database.write('DELETE FROM groups WHERE id=$1', [groupId], 'group-operator');
  const removed = await snapshots.snapshot(groupId);
  assert.equal(removed.deleted, true);
  assert.ok(BigInt(removed.revision) > BigInt(original.revision));
  await assert.rejects(database.write('INSERT INTO groups(id,name) VALUES($1,$2)', [groupId, 'Reused'], 'operator'), { code: '23514' });
  await assert.rejects(snapshots.snapshot(randomUUID()), { status: 404 });
});
test('a licensing snapshot waiting on a real metadata lock reads the committed name and matching revision after refresh',async()=>{
 const groupId=await group();const initial=await snapshots.snapshot(groupId);const blocker=await database.pool.connect();let pending;
 try{await blocker.query('BEGIN');await blocker.query("UPDATE groups SET name='Concurrent committed group name' WHERE id=$1",[groupId]);pending=snapshots.snapshot(groupId);pending.catch(()=>{});let waiting=false;
  for(let attempt=0;attempt<200;attempt++){waiting=(await database.query("SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'SELECT identity_membership_review_refresh(%'")).rows.length>0;if(waiting)break;await new Promise(resolve=>setTimeout(resolve,10));}assert.equal(waiting,true);await blocker.query('COMMIT');const current=await pending;assert.equal(current.name,'Concurrent committed group name');assert.ok(BigInt(current.revision)>BigInt(initial.revision));assert.deepEqual(snapshotContent(await snapshots.snapshot(groupId)),snapshotContent(current));
 }finally{await blocker.query('ROLLBACK');blocker.release();if(pending)await pending.catch(()=>{});}
});

test('missing identities cannot be inserted as members even with raw SQL', async () => {
  const groupId = await group(); const original = await snapshots.snapshot(groupId);
  await assert.rejects(add(groupId, randomUUID()), { code: '23503' });
  assert.equal((await snapshots.snapshot(groupId)).revision, original.revision);
});

test('legacy dangling memberships are reported explicitly instead of masquerading as enabled beneficiaries', async () => {
  const groupId = await group();
  await database.query('ALTER TABLE group_members DISABLE TRIGGER identity_member_validation;ALTER TABLE group_members DISABLE TRIGGER aaa_identity_tenant_membership_guard');
  try { await database.query("INSERT INTO group_members(group_id,user_id) VALUES($1,'legacy-unknown-user')", [groupId]); }
  finally { await database.query('ALTER TABLE group_members ENABLE TRIGGER identity_member_validation;ALTER TABLE group_members ENABLE TRIGGER aaa_identity_tenant_membership_guard'); }
  const result = await snapshots.snapshot(groupId);
  assert.deepEqual(result.memberIds, []);
  assert.deepEqual(result.unresolvedMemberIds, ['legacy-unknown-user']);
});

test('audit and outbox failure rolls back membership and revision changes', async () => {
  const groupId = await group(); const userId = await identity();
  const original = await snapshots.snapshot(groupId);
  await database.query("CREATE FUNCTION reject_outbox() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'injected outage'; END $$ LANGUAGE plpgsql; CREATE TRIGGER reject_outbox BEFORE INSERT ON identity_group_outbox FOR EACH ROW EXECUTE FUNCTION reject_outbox()");
  try {
    await assert.rejects(add(groupId, userId), /injected outage/);
    assert.equal((await snapshots.snapshot(groupId)).revision, original.revision);
    assert.deepEqual((await snapshots.snapshot(groupId)).memberIds, []);
  } finally { await database.query('DROP TRIGGER reject_outbox ON identity_group_outbox; DROP FUNCTION reject_outbox()'); }
});

test('an audit write failure cannot return a successful HTTP membership change', async () => {
  const groupId = await group(); const userId = await identity();
  const original = await snapshots.snapshot(groupId);
  await database.query("CREATE FUNCTION reject_group_audit() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'audit unavailable'; END $$ LANGUAGE plpgsql; CREATE TRIGGER reject_group_audit BEFORE INSERT ON identity_group_audit FOR EACH ROW EXECUTE FUNCTION reject_group_audit()");
  try {
    assert.equal((await groupApi('POST', `/api/groups/${groupId}/members`, { roles: ['group-administrator'] }, { userId })).status, 503);
    assert.deepEqual(snapshotContent(await snapshots.snapshot(groupId)),snapshotContent(original));
  } finally { await database.query('DROP TRIGGER reject_group_audit ON identity_group_audit; DROP FUNCTION reject_group_audit()'); }
});

test('group changes record the trusted actor and audit rows reject ordinary modification', async () => {
  const groupId = await group(); await add(groupId, await identity());
  const audit = await database.query('SELECT actor FROM identity_group_audit WHERE group_id=$1 ORDER BY revision DESC LIMIT 1', [groupId]);
  assert.equal(audit.rows[0].actor, 'membership-operator');
  assert.ok((await database.query("SELECT details->>'userId' AS user_id FROM identity_group_audit WHERE group_id=$1 AND action='member-added'", [groupId])).rows[0].user_id);
  await assert.rejects(database.query("UPDATE identity_group_audit SET actor='forged'"), { code: '42501' });
  await assert.rejects(database.query('DELETE FROM identity_group_audit'), { code: '42501' });
  assert.ok((await database.query('SELECT COUNT(*)::int AS count FROM identity_group_outbox WHERE published_at IS NULL')).rows[0].count >= 2);
});

test('reapplying migrations preserves revision history and snapshot data', async () => {
  const groupId = await group(); const userId = await identity(); await add(groupId, userId);
  const original = await snapshots.snapshot(groupId);
  await database.query(fs.readFileSync(path.join(__dirname, '../../migrations/002_group_snapshots.sql'), 'utf8'));
  assert.deepEqual(snapshotContent(await snapshots.snapshot(groupId)),snapshotContent(original));
});

test('signed license roles read snapshots without gaining general directory or membership rights', async () => {
  const groupId = await group(); const member = await identity(); await add(groupId, member);
  const reader = await pimPrincipal('license-manager');
  const result = await api('GET', `/api/license-groups/${groupId}/snapshot`, reader);
  assert.equal(result.status, 200); assert.deepEqual(result.body.memberIds, [member]);
  assert.equal(result.headers.get('cache-control'), 'no-store');
  assert.equal((await api('GET', '/api/users', reader)).status, 403);
  assert.equal((await groupApi('POST', `/api/groups/${groupId}/members`, reader, { userId: member })).status, 403);
  assert.equal((await api('GET', `/api/license-groups/${groupId}/snapshot`, { scope: 'identity.admin licenses.groups.read' })).status, 403);
  assert.equal((await api('GET', `/api/license-groups/${groupId}/snapshot`, { ...reader, token_use: 'id' })).status, 403);
});

test('direct user updates cannot smuggle roles or identifiers and status management requires a separate grant', async () => {
  const userId = await identity();
  assert.equal((await api('PUT', `/api/users/${userId}`, { permissions: ['users.update'] }, { enabled: false })).status, 403);
  assert.equal((await api('PUT', `/api/users/${userId}`, { roles: ['admin'] }, { id: randomUUID(), roles: ['admin'] })).status, 400);
  const current = await api('GET', `/api/users/${userId}`, { roles: ['directory-reader'] });
  assert.equal((await api('PUT', `/api/users/${userId}`, { permissions: ['users.update', 'users.status.manage'] }, { enabled: false }, { 'If-Match': current.headers.get('etag') })).status, 200);
});

test('membership HTTP operations are persisted, reversible, and attributed to the signed subject', async () => {
  const groupId = await group(); const member = await identity();
  assert.equal((await groupApi('POST', `/api/groups/${groupId}/members`, { roles: ['group-administrator'] }, { userId: member })).status, 200);
  const audit = await database.query('SELECT actor FROM identity_group_audit WHERE group_id=$1 ORDER BY revision DESC LIMIT 1', [groupId]);
  assert.equal(audit.rows[0].actor, 'native-directory-reader');
  assert.equal((await groupApi('DELETE', `/api/groups/${groupId}/members/${member}`, { roles: ['group-administrator'] })).status, 200);
  assert.deepEqual((await snapshots.snapshot(groupId)).memberIds, []);
});

test('metadata updates return the committed revision and cannot replace membership through a body field', async () => {
  const groupId = await group(); const original = await snapshots.snapshot(groupId);
  const updated = await groupApi('PUT', `/api/groups/${groupId}`, { roles: ['group-administrator'] }, { name: 'Renamed group' });
  assert.equal(updated.status, 200);
  assert.ok(BigInt(updated.body.revision) > BigInt(original.revision));
  assert.equal((await snapshots.snapshot(groupId)).revision, updated.body.revision);
  assert.equal((await groupApi('PUT', `/api/groups/${groupId}`, { roles: ['group-administrator'] }, { members: [await identity()] })).status, 400);
});

test('only trusted link administration can bind a signed subject and body claims cannot spoof the binding', async () => {
  const userId = await identity(); const other = await identity(); const groupId = await group(); await add(groupId, userId);
  const body = { issuer, subject: 'reviewer-alias', userId };
  assert.equal((await api('POST', '/api/identity/links', { roles: ['license-approver'] }, body)).status, 403);
  assert.equal((await api('POST', '/api/identity/links', { roles: ['admin'] }, body)).status, 201);
  await assert.rejects(database.query('UPDATE identity_subject_links SET user_id=$1 WHERE subject=$2', [other, 'reviewer-alias']), { code: '42501' });
  assert.equal((await api('POST', '/api/identity/links', { roles: ['admin'] }, { ...body, userId: other })).status, 409);
  assert.equal((await api('POST', '/api/identity/links', { roles: ['admin'] }, { ...body, issuer: 'https://untrusted.test' })).status, 400);
  await database.write("INSERT INTO identity_role_assignments(user_id,role,reason) VALUES($1,'license-approver','Explicit canonical snapshot reviewer fixture')", [userId], 'fixture');
  const reviewer = await pimRefresh({ sub: 'reviewer-alias' });
  const snapshot = await api('GET', `/api/license-groups/${groupId}/snapshot`, { ...reviewer, directory_user_id: other });
  assert.equal(snapshot.status, 200, JSON.stringify(snapshot.body));
  assert.equal(snapshot.body.viewerUserId, userId);
  assert.equal((await api('DELETE', '/api/identity/links', { roles: ['admin'] }, { issuer,subject:body.subject })).status, 204);
  assert.equal((await api('GET', `/api/license-groups/${groupId}/snapshot`, reviewer)).status, 401, 'Removing the actual issuer link invalidates the retained original actor/home proof');
  assert.equal((await api('GET', `/api/license-groups/${groupId}/snapshot`, { sub: 'reviewer-alias', roles: ['license-approver'] })).status, 403, 'A role-only unlinked alias cannot recreate canonical snapshot authority');
  const unlinked = await api('GET', '/api/identity/subject', { sub: 'reviewer-alias' });
  assert.equal(unlinked.status, 200); assert.equal(unlinked.body.userId, null);
  const audit = await database.query("SELECT actor FROM identity_link_audit WHERE details->>'subject'='reviewer-alias'");
  assert.deepEqual(audit.rows.map(row => row.actor), ['native-link-operator', 'native-link-operator']);
});

test('canonical user creation is disabled, versioned, strictly validated and attributed without provisioning credentials', async () => {
  const profile = { username: 'canonical-person', email: 'canonical@test.invalid', displayName: 'Canonical Person' };
  for (const extra of [{ enabled: true }, { role: 'admin' }, { password: 'not-a-credential-provisioner' }, { id: randomUUID() }]) {
    assert.equal((await api('POST', '/api/users', { roles: ['user-administrator'] }, { ...profile, ...extra })).status, 400);
  }
  const created = await api('POST', '/api/users', { roles: ['user-administrator'] }, profile);
  assert.equal(created.status, 201); assert.equal(created.body.enabled, false); assert.ok(BigInt(created.body.revision) > 0n);
  assert.equal(created.headers.get('etag'), `"user-${created.body.id}-${created.body.revision}"`);
  assert.equal(created.body.password, undefined); assert.equal(created.body.role, undefined); assert.equal(created.body.authorization_revision, undefined);
  const record = await api('GET', '/api/users/' + created.body.id, { roles: ['directory-reader'] }); assert.deepEqual(record.body, created.body);
  const audit = (await database.query('SELECT actor,action,details FROM identity_user_record_audit WHERE user_id=$1', [created.body.id])).rows;
  assert.equal(audit.length, 1); assert.equal(audit[0].actor, 'native-directory-reader'); assert.equal(audit[0].action, 'insert'); assert.equal(audit[0].details.after.enabled, false);
});

test('user pages and search use canonical usernames, bounded filters and correct empty responses', async () => {
  for (let position = 0; position < 31; position++) await database.write('INSERT INTO users(id,username,email,display_name,enabled) VALUES($1,$2,$3,$4,$5)',
    [randomUUID(), 'page-' + position, `page-${position}@test.invalid`, position === 0 ? 'Literal%Name' : 'Display ' + position, position % 2 === 0], 'fixture');
  const reader = { roles: ['directory-reader'] };
  const first = await api('GET', '/api/users', reader); const second = await api('GET', '/api/users?page=2', reader);
  assert.equal(first.body.users.length, 25); assert.equal(second.body.users.length, 7); assert.equal(second.body.total, 32); assert.equal(second.body.limit, 25);
  assert.equal(new Set([...first.body.users, ...second.body.users].map(user => user.id)).size, 32);
  assert.equal((await api('GET', '/api/users?search=page-30', reader)).body.users.length, 1);
  assert.equal((await api('GET', '/api/users?search=%25', reader)).body.users.length, 1);
  assert.equal((await api('GET', '/api/users?enabled=false', reader)).body.total, 15);
  assert.equal((await api('GET', '/api/users?search=not-present', reader)).body.total, 0);
  for (const query of ['page=0', 'limit=101', 'page[]=1', 'search[name]=other', 'enabled=yes', 'role=admin']) assert.equal((await api('GET', '/api/users?' + query, reader)).status, 400);
});

test('missing, weak, wildcard and stale user preconditions are rejected instead of overwriting or deleting newer records', async () => {
  const userId = await identity(); const administrator = { roles: ['admin'] };
  const original = await api('GET', `/api/users/${userId}`, administrator); const tag = original.headers.get('etag');
  assert.equal((await api('PUT', `/api/users/${userId}`, administrator, { title: 'No version' })).status, 428);
  assert.equal((await api('DELETE', `/api/users/${userId}`, administrator)).status, 428);
  for (const expected of ['*', 'W/' + tag, tag + ',' + tag]) assert.equal((await api('PUT', `/api/users/${userId}`, administrator, { title: 'Invalid version' }, { 'If-Match': expected })).status, 400);
  const current = await api('PUT', `/api/users/${userId}`, administrator, { title: 'New version' }, { 'If-Match': tag }); assert.equal(current.status, 200);
  assert.notEqual(current.headers.get('etag'), tag);
  assert.equal((await api('DELETE', `/api/users/${userId}`, administrator, undefined, { 'If-Match': tag })).status, 412);
  assert.equal((await api('DELETE', `/api/users/${userId}`, administrator, undefined, { 'If-Match': current.headers.get('etag') })).status, 204);
  assert.equal((await api('GET', `/api/users/${userId}`, administrator)).status, 404);
});

test('a stale profile editor cannot undo a committed account disable or smuggle enabled without a separate status grant', async () => {
  const userId = await identity(); const reader = { roles: ['directory-reader'] }; const editor = { permissions: ['users.read', 'users.update'] };
  const original = await api('GET', `/api/users/${userId}`, reader); const tag = original.headers.get('etag');
  const disabled = await api('PUT', `/api/users/${userId}`, { roles: ['user-lifecycle-operator'] }, { enabled: false }, { 'If-Match': tag }); assert.equal(disabled.status, 200);
  assert.equal((await api('PUT', `/api/users/${userId}`, editor, { title: 'Stale editor' }, { 'If-Match': tag })).status, 412);
  const currentTag = disabled.headers.get('etag');
  assert.equal((await api('PUT', `/api/users/${userId}`, editor, { enabled: true }, { 'If-Match': currentTag })).status, 403);
  const before = (await database.query('SELECT authorization_revision FROM users WHERE id=$1', [userId])).rows[0].authorization_revision;
  const updated = await api('PUT', `/api/users/${userId}`, editor, { title: 'Allowed profile edit' }, { 'If-Match': currentTag });
  assert.equal(updated.status, 200); assert.equal(updated.body.enabled, false);
  assert.equal((await database.query('SELECT authorization_revision FROM users WHERE id=$1', [userId])).rows[0].authorization_revision, before);
});

test('two concurrent writers with one user ETag have exactly one winner and one audited update', async () => {
  const userId = await identity(); const editor = { permissions: ['users.read', 'users.update'] }; const tag = (await api('GET', `/api/users/${userId}`, editor)).headers.get('etag');
  const results = await Promise.all(['First', 'Second'].map(title => api('PUT', `/api/users/${userId}`, editor, { title }, { 'If-Match': tag })));
  assert.deepEqual(results.map(result => result.status).sort(), [200, 412]);
  assert.equal((await database.query("SELECT COUNT(*)::int AS count FROM identity_user_record_audit WHERE user_id=$1 AND action='update'", [userId])).rows[0].count, 1);
});

test('profile and status writes roll back with the record revision when their audit cannot commit', async () => {
  const userId = await identity(); const administrator = { roles: ['admin'] }; const original = await api('GET', `/api/users/${userId}`, administrator);
  await database.query('ALTER TABLE identity_user_record_audit RENAME TO unavailable_record_audit');
  try {
    assert.equal((await api('PUT', `/api/users/${userId}`, administrator, { enabled: false, title: 'Must roll back' }, { 'If-Match': original.headers.get('etag') })).status, 503);
    const current = await api('GET', `/api/users/${userId}`, administrator); assert.deepEqual(current.body, original.body); assert.equal(current.headers.get('etag'), original.headers.get('etag'));
  } finally { await database.query('ALTER TABLE unavailable_record_audit RENAME TO identity_user_record_audit'); }
  await assert.rejects(database.query('UPDATE identity_user_record_audit SET actor=$1 WHERE user_id=$2', ['forged', userId]), /append-only/);
});

test('reapplying the user-record migration preserves existing versions and later writes advance them', async () => {
  const userId = await identity(); const administrator = { roles: ['admin'] }; const original = await api('GET', `/api/users/${userId}`, administrator);
  await database.query(fs.readFileSync(path.join(__dirname, '../../migrations/006_directory_user_records.sql'), 'utf8'));
  const current = await api('GET', `/api/users/${userId}`, administrator); assert.deepEqual(current.body, original.body); assert.equal(current.headers.get('etag'), original.headers.get('etag'));
  const updated = await api('PUT', `/api/users/${userId}`, administrator, { title: 'Post-migration edit' }, { 'If-Match': original.headers.get('etag') });
  assert.equal(updated.status, 200); assert.ok(BigInt(updated.body.revision) > BigInt(original.body.revision));
});

async function roleActor(role = 'role-administrator') {
  const userId = await identity();const subject = randomUUID();
  await database.write('INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES($1,$2,$3)',[issuer,subject,userId],'Explicit canonical role operator fixture');
  await database.write('INSERT INTO identity_role_assignments(user_id,role,reason) VALUES($1,$2,$3)',[userId,role,'Explicit canonical role operator fixture'],'Explicit canonical role operator fixture');
  const current=await new AuthorizationState(database).state(issuer,subject);
  return { actor_type:'user',iss:issuer,sub:subject,roles:current.roles,identity_authorization:current.context };
}
const roleBody = { role: 'license-manager', durationSeconds: 3600, reason: 'Reviewed license management delegation' };

test('role administration is independent of directory profile reads and writes and records a canonical actor', async () => {
  const target = await identity(); const operator = await roleActor();
  const before = (await database.query('SELECT authorization_revision FROM users WHERE id=$1', [target])).rows[0].authorization_revision;
  for (const roles of [['user-administrator'], ['directory-reader'], ['session-administrator']]) {
    assert.equal((await api('POST', `/api/users/${target}/roles`, { roles }, roleBody)).status, 403);
  }
  const created = await api('POST', `/api/users/${target}/roles`, operator, roleBody);
  assert.equal(created.status, 201); assert.equal(created.body.role, roleBody.role); assert.equal(created.body.userId, target);
  assert.equal(created.body.status, 'active'); assert.ok(new Date(created.body.expiresAt) - new Date(created.body.createdAt) > 3599000);
  assert.equal((await api('GET', '/api/users', operator)).status, 403);
  const listed = await api('GET', `/api/users/${target}/roles`, { roles: ['role-reader'] }); assert.equal(listed.status, 200); assert.equal(listed.body.assignments.length, 1);
  assert.equal((await api('POST', `/api/users/${target}/roles`, { roles: ['role-reader'] }, roleBody)).status, 403);
  assert.ok(BigInt((await database.query('SELECT authorization_revision FROM users WHERE id=$1', [target])).rows[0].authorization_revision) > BigInt(before));
  const audit = (await database.query('SELECT * FROM identity_role_audit WHERE user_id=$1', [target])).rows[0];
  assert.equal(audit.action, 'granted'); assert.equal(JSON.parse(audit.actor).userId, operator.identity_authorization.userId);
});
test('role managers cannot administer their own canonical ID, protected roles, arbitrary permissions or unbounded durations', async () => {
  const operator = await roleActor(); const target = await identity();
  assert.equal((await api('POST', `/api/users/${operator.identity_authorization.userId.toUpperCase()}/roles`, operator, roleBody)).status, 403);
  for (const role of ['admin', 'role-administrator']) assert.equal((await api('POST', `/api/users/${target}/roles`, operator, { ...roleBody, role })).status, 403);
  for (const patch of [{ durationSeconds: 28801 }, { durationSeconds: 59 }, { expiresAt: null }, { permissions: ['users.delete'] }, { role: 'fake-admin' }]) {
    assert.equal((await api('POST', `/api/users/${target}/roles`, operator, { ...roleBody, ...patch })).status, 400);
  }
  const catalog = await api('GET', '/api/identity/roles/catalog', operator); assert.equal(catalog.status, 200);
  assert.equal(catalog.body.roles.find(item => item.role === 'admin').assignable, false);
  assert.equal((await api('POST', `/api/users/${target}/roles?role=admin`, operator, roleBody)).status, 400);
  assert.equal((await api('GET', `/api/users/${target}/roles?include=credentials`, operator)).status, 400);
  assert.equal((await api('POST', `/api/users/${target}/roles`, { ...operator, actor_type: 'application' }, roleBody)).status, 403);
});
test('role grants are immutable, revocation is one-way and append-only evidence cannot be edited', async () => {
  const target = await identity(); const operator = await roleActor(); const created = await api('POST', `/api/users/${target}/roles`, operator, roleBody);
  for (const sql of ["UPDATE identity_role_assignments SET role='admin' WHERE id=$1", "UPDATE identity_role_assignments SET expires_at=NULL WHERE id=$1", 'DELETE FROM identity_role_assignments WHERE id=$1']) {
    await assert.rejects(database.query(sql, [created.body.id]), error => error.code === '23514');
  }
  const route = `/api/users/${target}/roles/${created.body.id}`;
  assert.equal((await api('DELETE', route, operator)).status, 200); assert.equal((await api('DELETE', route, operator)).status, 200);
  assert.equal((await api('GET', `/api/users/${target}/roles`, operator)).body.assignments[0].status, 'revoked');
  await assert.rejects(database.query('UPDATE identity_role_assignments SET revoked_at=NULL WHERE id=$1', [created.body.id]), error => error.code === '23514');
  await assert.rejects(database.query('UPDATE identity_role_audit SET actor=$1 WHERE user_id=$2', ['forged', target]), /append-only/);
  assert.equal((await database.query("SELECT COUNT(*)::int AS count FROM identity_role_audit WHERE user_id=$1 AND action='revoked'", [target])).rows[0].count, 1);
});
test('role audit failure rolls back the grant, revocation and authorization generation together', async () => {
  const target = await identity(); const operator = await roleActor(); const created = await api('POST', `/api/users/${target}/roles`, operator, roleBody);
  const original = (await database.query('SELECT authorization_revision,record_revision FROM users WHERE id=$1', [target])).rows[0];
  await database.query('ALTER TABLE identity_role_audit RENAME TO unavailable_role_audit');
  try {
    assert.equal((await api('POST', `/api/users/${target}/roles`, operator, roleBody)).status, 503);
    assert.equal((await api('DELETE', `/api/users/${target}/roles/${created.body.id}`, operator)).status, 503);
    assert.equal((await database.query('SELECT revoked_at FROM identity_role_assignments WHERE id=$1', [created.body.id])).rows[0].revoked_at, null);
    assert.deepEqual((await database.query('SELECT authorization_revision,record_revision FROM users WHERE id=$1', [target])).rows[0], original);
    assert.equal((await database.query('SELECT COUNT(*)::int AS count FROM identity_role_assignments WHERE user_id=$1', [target])).rows[0].count, 1);
  } finally { await database.query('ALTER TABLE unavailable_role_audit RENAME TO identity_role_audit'); }
});
test('concurrent role grants serialize the active per-user bound instead of overflowing it', async () => {
  const target = await identity(); const operator = await roleActor();
  await database.write("INSERT INTO identity_role_assignments(user_id,role,reason) SELECT $1,'user','Explicit disposable limit fixture' FROM generate_series(1,99)", [target], 'fixture');
  const results = await Promise.all([1, 2].map(() => api('POST', `/api/users/${target}/roles`, operator, roleBody)));
  assert.deepEqual(results.map(result => result.status).sort(), [201, 409]);
  assert.equal((await database.query('SELECT COUNT(*)::int AS count FROM identity_role_assignments WHERE user_id=$1', [target])).rows[0].count, 100);
});
test('deleted users retain role evidence without permitting identity resurrection or dangling new grants', async () => {
  const target = await identity(); const operator = await roleActor(); const created = await api('POST', `/api/users/${target}/roles`, operator, roleBody);
  await database.write('DELETE FROM users WHERE id=$1', [target], 'lifecycle');
  assert.equal((await api('GET', `/api/users/${target}/roles`, operator)).status, 404);
  assert.equal((await database.query('SELECT COUNT(*)::int AS count FROM identity_role_assignments WHERE id=$1', [created.body.id])).rows[0].count, 1);
  await assert.rejects(database.write("INSERT INTO identity_role_assignments(user_id,role,reason) VALUES($1,'admin','Must not create dangling privilege')", [target], 'fixture'), error => error.code === '23503');
});
test('offline reviewed bootstrap and migration reapplication preserve the role authority without importing credential roles', async () => {
  const target = await identity(); const { bootstrapRole } = require('../../scripts/bootstrap-role');
  const granted = await bootstrapRole(database, { userId: target, role: 'admin', duration: null, reason: 'Reviewed recovery account bootstrap' });
  const before = (await database.query('SELECT authorization_revision FROM users WHERE id=$1', [target])).rows[0];
  await database.query(fs.readFileSync(path.join(__dirname, '../../migrations/007_directory_roles.sql'), 'utf8'));
  assert.deepEqual((await database.query('SELECT authorization_revision FROM users WHERE id=$1', [target])).rows[0], before);
  assert.equal((await database.query('SELECT expires_at FROM identity_role_assignments WHERE id=$1', [granted.id])).rows[0].expires_at, null);
  assert.equal(JSON.parse((await database.query('SELECT actor FROM identity_role_audit WHERE assignment_id=$1', [granted.id])).rows[0].actor).kind, 'offline-bootstrap');
});

const pimPath = '/api/identity/pim';
async function pimPrincipal(role = 'user') {
  const userId = await identity(); const subject = randomUUID();
  await database.write('INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES($1,$2,$3)', [issuer, subject, userId], 'fixture');
  await database.write('INSERT INTO identity_role_assignments(user_id,role,reason) VALUES($1,$2,$3)', [userId, role, 'Explicit disposable PIM fixture'], 'fixture');
  return pimRefresh({ sub: subject, userId });
}

const membershipPath='/api/identity/membership-reviews';
const membershipReason='Independent explicit canonical group-membership governance';
async function membershipFixture(prepare=true){
 const manager=await pimPrincipal('group-review-administrator');const voter=await pimPrincipal('group-reviewer');const creator=await pimPrincipal('group-administrator');const owner=await pimPrincipal();const groupId=await group();
 if(prepare)assert.equal((await groupApi('POST','/api/groups/'+groupId+'/members',creator,{userId:owner.userId})).status,200);
 const settings={groupId,intervalSeconds:300,windowSeconds:60,reviewerUserIds:[voter.userId],reason:membershipReason,acknowledgeEffects:true};const configured=await api('POST',membershipPath+'/policies',manager,settings);assert.equal(configured.status,201,JSON.stringify(configured.body));
 return{manager,voter,creator,owner,groupId,settings,policy:configured};
}
async function membershipRows(fixture){const result=await api('GET',membershipPath+'/assigned',fixture.voter);assert.equal(result.status,200,JSON.stringify(result.body));return result.body.reviews;}
function membershipDecision(fixture,row,decision='retain',actor=fixture.voter){return api('POST',membershipPath+'/'+row.id+'/decisions',actor,{decision,reason:membershipReason,acknowledgeScope:true},{'If-Match':`"od-membership-review:${row.id}:${row.version}:${row.policyVersion}"`});}
async function membershipTime(seconds){await database.query(`CREATE OR REPLACE FUNCTION identity_membership_review_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+interval '${seconds} seconds'; $$`);}
test('existing canonical memberships are captured with bounded grace and independent recurring recertification',async()=>{
 const fixture=await membershipFixture();const row=(await membershipRows(fixture))[0];assert.equal(row.state,'pending');assert.equal(row.legacyOrigin,false);assert.equal(row.canRetain,true);assert.equal((await snapshots.snapshot(fixture.groupId)).memberIds[0],fixture.owner.userId);
 const retained=await membershipDecision(fixture,row);assert.equal(retained.status,200,JSON.stringify(retained.body));assert.equal(retained.body.cycle,'2');assert.equal(retained.body.state,'scheduled');assert.equal(retained.body.membershipId,row.membershipId);assert.equal((await membershipDecision(fixture,row)).status,412);
 const evidence=(await database.query("SELECT actor FROM identity_membership_review_audit WHERE review_id=$1 AND action='retain'",[row.id])).rows[0].actor;assert.equal(evidence.authTime,fixture.voter.auth_time);assert.equal(evidence.factorRevision,fixture.voter.mfa_authorization.revision);assert.equal(evidence.rolesRevision,fixture.voter.identity_authorization.rolesRevision);assert.equal(evidence.authorization,undefined);
});
test('new governed memberships grant neither application membership nor licensing source authority before an independent vote',async()=>{
 const fixture=await membershipFixture(false);const added=await groupApi('POST','/api/groups/'+fixture.groupId+'/members',fixture.creator,{userId:fixture.owner.userId});assert.equal(added.status,200);const row=(await membershipRows(fixture))[0];assert.deepEqual(added.body.membershipReview,{required:true,membershipId:row.membershipId,effective:false});assert.equal(row.state,'awaiting');assert.equal(row.effective,false);
 const source=new AuthorizationState(database);assert.deepEqual((await source.state(issuer,fixture.owner.sub)).memberships,[]);const pending=await snapshots.snapshot(fixture.groupId);assert.deepEqual(pending.memberIds,[]);assert.deepEqual(pending.inactiveMemberIds,[fixture.owner.userId]);assert.equal((await source.target('group',fixture.groupId,fixture.owner.userId)).actorIsMember,true);
 assert.equal((await membershipDecision(fixture,row)).status,200);assert.equal((await source.state(issuer,fixture.owner.sub)).memberships[0].membershipId,row.membershipId);const active=await snapshots.snapshot(fixture.groupId);assert.ok(BigInt(active.revision)>BigInt(pending.revision));assert.deepEqual(active.memberIds,[fixture.owner.userId]);
});
test('an unanswered cutoff removes actual membership and advances the licensing snapshot exactly once without a scheduler',async()=>{
 const fixture=await membershipFixture();const row=(await membershipRows(fixture))[0];const first=await snapshots.snapshot(fixture.groupId);await membershipTime(61);const[next,parallel]=await Promise.all([snapshots.snapshot(fixture.groupId),snapshots.snapshot(fixture.groupId)]);assert.deepEqual(next.memberIds,[]);assert.ok(BigInt(next.revision)>BigInt(first.revision));assert.equal(parallel.revision,next.revision);assert.equal((await snapshots.snapshot(fixture.groupId)).revision,next.revision);
 assert.deepEqual((await new AuthorizationState(database).state(issuer,fixture.owner.sub)).memberships,[]);assert.equal((await database.query('SELECT count(*)::int AS count FROM group_members WHERE group_id=$1',[fixture.groupId])).rows[0].count,1);assert.equal((await membershipDecision(fixture,row)).status,403);
});
test('denial withdraws only the exact actual membership and leaves another group and the user enabled',async()=>{
 const fixture=await membershipFixture();const other=await group();await add(other,fixture.owner.userId);const row=(await membershipRows(fixture))[0];const denied=await membershipDecision(fixture,row,'deny');assert.equal(denied.status,200,JSON.stringify(denied.body));assert.equal(denied.body.state,'denied');assert.equal(denied.body.effective,false);
 assert.deepEqual((await database.query('SELECT group_id FROM group_members WHERE user_id=$1',[fixture.owner.userId])).rows.map(value=>value.group_id),[other]);assert.equal((await database.query('SELECT enabled FROM users WHERE id=$1',[fixture.owner.userId])).rows[0].enabled,true);
});
test('a group grantor, configurator or any configured member cannot serve as its independent voter',async()=>{
 const fixture=await membershipFixture();assert.equal((await api('POST',membershipPath+'/policies',fixture.manager,{...fixture.settings,groupId:await group(),reviewerUserIds:[fixture.manager.userId]})).status,400);
 await database.write('INSERT INTO identity_role_assignments(user_id,role,reason) VALUES($1,$2,$3)',[fixture.creator.userId,'group-reviewer',membershipReason],'fixture');const creator=await pimRefresh(fixture.creator);const retired=await api('POST',membershipPath+'/policies/'+fixture.policy.body.id+'/retire',fixture.manager,{reason:membershipReason,acknowledgeEffects:true},{'If-Match':fixture.policy.headers.get('etag')});assert.equal(retired.status,200);
 assert.equal((await api('POST',membershipPath+'/policies',fixture.manager,{...fixture.settings,reviewerUserIds:[creator.userId]})).status,409);
 assert.equal((await membershipDecision(fixture,(await membershipRows(fixture))[0],'deny',fixture.owner)).status,403);
});
test('retirement and replacement preserve old cutoffs and cannot reopen unreviewed future membership insertion',async()=>{
 const fixture=await membershipFixture();const row=(await membershipRows(fixture))[0];assert.equal((await api('POST',membershipPath+'/policies/'+fixture.policy.body.id+'/retire',fixture.manager,{reason:membershipReason,acknowledgeEffects:true},{'If-Match':fixture.policy.headers.get('etag')})).status,200);
 const newcomer=await pimPrincipal();assert.equal((await groupApi('POST','/api/groups/'+fixture.groupId+'/members',fixture.creator,{userId:newcomer.userId})).status,409);assert.equal((await api('POST',membershipPath+'/policies',fixture.manager,fixture.settings)).status,201);const old=await api('GET',membershipPath+'/'+row.id,fixture.voter);assert.equal(old.body.deadlineAt,row.deadlineAt);assert.equal(old.body.policyVersion,'2');assert.equal(old.body.canRetain,false);await membershipTime(61);assert.deepEqual((await snapshots.snapshot(fixture.groupId)).memberIds,[]);
});
test('remove and readd uses a new waiting incarnation rather than resurrecting an expired approval',async()=>{
 const fixture=await membershipFixture();const row=(await membershipRows(fixture))[0];await membershipTime(61);assert.equal((await groupApi('DELETE','/api/groups/'+fixture.groupId+'/members/'+fixture.owner.userId,fixture.creator)).status,200);assert.equal((await groupApi('POST','/api/groups/'+fixture.groupId+'/members',fixture.creator,{userId:fixture.owner.userId})).status,200);
 const next=(await membershipRows(fixture)).find(value=>value.membershipId!==row.membershipId);assert.ok(next);assert.equal(next.effective,false);assert.equal(next.state,'awaiting');assert.deepEqual((await snapshots.snapshot(fixture.groupId)).memberIds,[]);assert.equal((await membershipDecision(fixture,next)).status,200);assert.deepEqual((await snapshots.snapshot(fixture.groupId)).memberIds,[fixture.owner.userId]);
});
test('legacy unproven membership origins are never retroactively blessed as independently issued grants',async()=>{
 const fixture=await membershipFixture(false);const legacy=await group();await add(legacy,fixture.owner.userId);assert.equal((await api('POST',membershipPath+'/policies',fixture.manager,{...fixture.settings,groupId:legacy})).status,201);const row=(await membershipRows(fixture)).find(value=>value.groupId===legacy);assert.equal(row.legacyOrigin,true);assert.equal(row.canRetain,false);assert.equal(row.canDeny,true);assert.equal((await membershipDecision(fixture,row)).status,403);assert.equal((await membershipDecision(fixture,row,'deny')).status,200);
});
test('ordinary global administration is not an implicit new review duty and read-only metadata cannot mutate membership',async()=>{
 const fixture=await membershipFixture();const root=await pimPrincipal('admin');const reader=await pimPrincipal('group-review-reader');const row=(await membershipRows(fixture))[0];assert.equal((await api('POST',membershipPath+'/policies',root,fixture.settings)).status,403);assert.equal((await membershipDecision(fixture,row,'deny',root)).status,403);assert.equal((await api('GET',membershipPath+'/'+row.id,reader)).body.canDeny,false);assert.equal((await groupApi('POST','/api/groups/'+fixture.groupId+'/members',reader,{userId:reader.userId})).status,403);
 const own=await api('GET',membershipPath+'/self',fixture.owner);assert.equal(own.body.reviews[0].id,row.id);assert.equal(own.body.reviews[0].canDeny,false);assert.equal((await api('GET',membershipPath+'/'+row.id+'?roles=admin',reader)).status,400);
});
test('concurrent membership review decisions consume exactly one captured generation',async()=>{
 const fixture=await membershipFixture();const row=(await membershipRows(fixture))[0];const results=await Promise.all([membershipDecision(fixture,row),membershipDecision(fixture,row,'deny')]);assert.deepEqual(results.map(value=>value.status).sort(),[200,412]);
});
test('disable and re-enable cannot revive the reviewed membership incarnation',async()=>{
 const fixture=await membershipFixture();const row=(await membershipRows(fixture))[0];assert.equal((await membershipDecision(fixture,row)).status,200);await database.write('UPDATE users SET enabled=false WHERE id=$1',[fixture.owner.userId],'fixture-disable');await database.write('UPDATE users SET enabled=true WHERE id=$1',[fixture.owner.userId],'fixture-enable');assert.deepEqual((await snapshots.snapshot(fixture.groupId)).memberIds,[]);assert.deepEqual((await new AuthorizationState(database).state(issuer,fixture.owner.sub)).memberships,[]);
});
test('governed additions require actual fresh MFA rather than group-manager role labels',async()=>{
 const fixture=await membershipFixture(false);assert.equal((await groupApi('POST','/api/groups/'+fixture.groupId+'/members',{...fixture.creator,mfa_authorization:undefined},{userId:fixture.owner.userId})).status,428);assert.equal((await database.query('SELECT count(*)::int AS count FROM group_members WHERE group_id=$1',[fixture.groupId])).rows[0].count,0);
});
test('post-DML loss of original issuer authority rolls back both membership denial and immutable evidence',async()=>{
 const fixture=await membershipFixture();const row=(await membershipRows(fixture))[0];let calls=0;const store=new(require('../GroupMembershipReviews').GroupMembershipReviews)(database,{revalidate:async()=>{if(++calls===2)throw Object.assign(new Error('Owned original issuer withdrawal'),{status:401});}});const before=(await database.query('SELECT count(*)::int AS count FROM identity_membership_review_audit')).rows[0].count;
 await assert.rejects(store.decide(row.id,`"od-membership-review:${row.id}:1:1"`,{decision:'deny',reason:membershipReason,acknowledgeScope:true},{...fixture.voter,iss:issuer},'Bearer owned'),error=>error.status===401);assert.equal((await database.query('SELECT count(*)::int AS count FROM group_members WHERE group_id=$1',[fixture.groupId])).rows[0].count,1);assert.equal((await database.query('SELECT count(*)::int AS count FROM identity_membership_review_audit')).rows[0].count,before);
});
test('review audit failure cannot confirm a cutoff projection with an unchanged licensing revision',async()=>{
 const fixture=await membershipFixture();const original=await snapshots.snapshot(fixture.groupId);await membershipTime(61);await database.query("CREATE FUNCTION fail_membership_projection() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='refresh' THEN RAISE EXCEPTION 'Owned projection audit failure';END IF;RETURN NEW;END;$$;CREATE TRIGGER fail_membership_projection BEFORE INSERT ON identity_membership_review_audit FOR EACH ROW EXECUTE FUNCTION fail_membership_projection()");
 try{await assert.rejects(snapshots.snapshot(fixture.groupId));assert.deepEqual((await new AuthorizationState(database).state(issuer,fixture.owner.sub)).memberships,[]);}finally{await database.query('DROP TRIGGER fail_membership_projection ON identity_membership_review_audit;DROP FUNCTION fail_membership_projection()');}
 const current=await snapshots.snapshot(fixture.groupId);assert.ok(BigInt(current.revision)>BigInt(original.revision));assert.deepEqual(current.memberIds,[]);
});
test('review origin and history cannot be overwritten, deleted or extended through raw SQL',async()=>{
 const fixture=await membershipFixture();for(const sql of ['UPDATE identity_membership_origins SET created_by=NULL','DELETE FROM identity_membership_review_policies','UPDATE identity_membership_review_leases SET deadline_at=deadline_at+interval \'1 day\'','DELETE FROM identity_membership_review_audit'])await assert.rejects(database.query(sql),error=>error.code==='42501');
 const before=(await database.query('SELECT * FROM identity_membership_review_leases')).rows[0];await database.query(fs.readFileSync(path.join(__dirname,'../../migrations/019_group_membership_reviews.sql'),'utf8'));for(const file of ['029_scoped_group_reviews.sql','051_company_group_rule_automation.sql','052_live_company_group_rules.sql','053_company_automation_changes.sql'])await database.query(fs.readFileSync(path.join(__dirname,'../../migrations',file),'utf8'));assert.deepEqual((await database.query('SELECT * FROM identity_membership_review_leases')).rows[0],before);
});
test('adding the only voter to its governed group cannot eliminate the independent path or commit an awaiting source',async()=>{
 const fixture=await membershipFixture(false);assert.equal((await groupApi('POST','/api/groups/'+fixture.groupId+'/members',fixture.creator,{userId:fixture.voter.userId})).status,409);assert.equal((await database.query('SELECT count(*)::int AS count FROM group_members WHERE group_id=$1',[fixture.groupId])).rows[0].count,0);assert.equal((await database.query('SELECT count(*)::int AS count FROM identity_membership_origins WHERE group_id=$1',[fixture.groupId])).rows[0].count,0);
});
test('original group-writer issuer loss after insertion rolls back the membership, origin, capture and revision',async()=>{
 const fixture=await membershipFixture(false);const before=(await database.query('SELECT revision FROM groups WHERE id=$1',[fixture.groupId])).rows[0].revision;let calls=0;const store=new(require('../GroupMembershipReviews').GroupMembershipReviews)(database,{revalidate:async()=>{if(++calls===2)throw Object.assign(new Error('Owned group-writer authority loss'),{status:401});}});
 await assert.rejects(store.add(fixture.groupId,fixture.owner.userId,{...fixture.creator,iss:issuer},'Bearer owned'),error=>error.status===401);assert.equal((await database.query('SELECT count(*)::int AS count FROM group_members WHERE group_id=$1',[fixture.groupId])).rows[0].count,0);assert.equal((await database.query('SELECT revision FROM groups WHERE id=$1',[fixture.groupId])).rows[0].revision,before);
});
test('a first approval crossing its original response deadline during the final issuer call cannot open membership',async()=>{
 await administration.query('CREATE TABLE '+clockSchema+'.membership_clock(offset_seconds integer NOT NULL);INSERT INTO '+clockSchema+'.membership_clock VALUES(0)');await database.query("CREATE OR REPLACE FUNCTION identity_membership_review_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+offset_seconds*interval '1 second' FROM "+clockSchema+".membership_clock; $$");
 const fixture=await membershipFixture(false);assert.equal((await groupApi('POST','/api/groups/'+fixture.groupId+'/members',fixture.creator,{userId:fixture.owner.userId})).status,200);const row=(await membershipRows(fixture))[0];let calls=0;const store=new(require('../GroupMembershipReviews').GroupMembershipReviews)(database,{revalidate:async()=>{if(++calls===2)await administration.query('UPDATE '+clockSchema+'.membership_clock SET offset_seconds=61');}});
 try{await assert.rejects(store.decide(row.id,`"od-membership-review:${row.id}:1:1"`,{decision:'retain',reason:membershipReason,acknowledgeScope:true},{...fixture.voter,iss:issuer},'Bearer owned'),error=>error.status===409);assert.equal((await database.query('SELECT version FROM identity_membership_review_leases WHERE id=$1',[row.id])).rows[0].version,'1');assert.deepEqual((await new AuthorizationState(database).state(issuer,fixture.owner.sub)).memberships,[]);}
 finally{await membershipTime(0);await administration.query('DROP TABLE '+clockSchema+'.membership_clock');}
});
test('removed historical memberships cannot crowd a current waiting target out of the bounded assigned queue',async()=>{
 const fixture=await membershipFixture(false);const store=new(require('../GroupMembershipReviews').GroupMembershipReviews)(database,{revalidate:async()=>{}});const actor={...fixture.creator,iss:issuer};
 for(let attempt=0;attempt<101;attempt++){await store.add(fixture.groupId,fixture.owner.userId,actor,'Bearer owned');await database.write('DELETE FROM group_members WHERE group_id=$1',[fixture.groupId],'fixture-remove-old-incarnation');}
 await store.add(fixture.groupId,fixture.owner.userId,actor,'Bearer owned');const current=await api('GET',membershipPath+'/assigned',fixture.voter);assert.equal(current.body.reviews.length,1);assert.equal(current.body.truncated,false);assert.equal(current.body.reviews[0].state,'awaiting');
});

const roleReviewPath='/api/identity/reviews';
async function reviewFixture() {
  const manager=await pimPrincipal('access-review-administrator'); const reviewer=await pimPrincipal('access-reviewer'); const owner=await pimPrincipal('license-manager');
  const created=await api('POST',roleReviewPath+'/policies',manager,{ role:'license-manager',intervalSeconds:3600,windowSeconds:60,reviewerUserIds:[reviewer.userId],reason:'Independent recurring license-role review',acknowledgeDeadlines:true });
  assert.equal(created.status,201,JSON.stringify(created.body));
  const queue=await api('GET',roleReviewPath+'/self',reviewer); assert.equal(queue.status,200); assert.equal(queue.body.reviews.length,1);
  return { manager,reviewer,owner,policy:created.body,review:queue.body.reviews[0] };
}
function reviewDecision(fixture,decision='retain',principal=fixture.reviewer) {
  return api('POST',`${roleReviewPath}/${fixture.review.id}/decisions`,principal,{ decision,reason:'Independent actual entitlement recertification',acknowledgeScope:true },{ 'If-Match':`"od-role-review:${fixture.review.id}:${fixture.review.version}:${fixture.review.policyVersion}"` });
}
async function reviewTime(seconds) {
  assert.ok(Number.isInteger(seconds) && seconds>=0);
  await database.query(`CREATE OR REPLACE FUNCTION identity_role_review_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+interval '${seconds} seconds'; $$`);
}
test('review duties separate configuration, named review and read-only metadata without granting role or license administration',async()=>{
  const fixture=await reviewFixture(); const reader=await pimPrincipal('access-review-reader');
  for(const principal of [fixture.manager,fixture.reviewer,reader]) {
    assert.equal((await api('GET','/api/users',principal)).status,403);
    assert.equal((await api('POST','/api/users/'+fixture.owner.userId+'/roles',principal,{})).status,403);
  }
  assert.equal((await api('GET',roleReviewPath+'/'+fixture.review.id,reader)).body.canDecide,false);
  assert.equal((await reviewDecision(fixture,'retain',fixture.manager)).status,403);
  assert.equal((await reviewDecision(fixture,'retain',reader)).status,403);
  assert.equal((await api('POST',roleReviewPath+'/policies',fixture.reviewer,{})).status,403);
  assert.equal((await api('GET',roleReviewPath+'/self',fixture.owner)).status,403);
  assert.equal((await api('GET',roleReviewPath+'/'+fixture.review.id,fixture.owner)).status,404);
  assert.equal((await api('GET',roleReviewPath+'/'+fixture.review.id+'?actor=admin',reader)).status,400);
});
test('an independent retain advances the durable review cycle but never extends the canonical grant lifetime',async()=>{
  const fixture=await reviewFixture(); const before=(await database.query('SELECT * FROM identity_role_assignments WHERE id=$1',[fixture.review.targetId])).rows[0];
  const source=await new AuthorizationState(database).state(issuer,fixture.owner.sub);
  const retained=await reviewDecision(fixture); assert.equal(retained.status,200,JSON.stringify(retained.body));
  assert.equal(retained.body.state,'scheduled'); assert.equal(retained.body.version,'2'); assert.equal(retained.body.cycle,'2');
  assert.equal(Date.parse(retained.body.deadlineAt)-Date.parse(fixture.review.deadlineAt),3600000);
  assert.deepEqual((await database.query('SELECT * FROM identity_role_assignments WHERE id=$1',[fixture.review.targetId])).rows[0],before);
  const after=await new AuthorizationState(database).state(issuer,fixture.owner.sub); assert.deepEqual(after.roles,['license-manager']); assert.notEqual(after.context.rolesRevision,source.context.rolesRevision);
  assert.equal((await reviewDecision(fixture)).status,412);
  assert.equal((await reviewDecision({ ...fixture,review:retained.body })).status,409);
  await reviewTime(3601); const next=await api('GET',roleReviewPath+'/'+fixture.review.id,fixture.reviewer); assert.equal(next.body.state,'pending'); assert.equal(next.body.canDecide,true);
});
test('an unanswered deadline withdraws runtime authority without a scheduler and retirement/replacement cannot revive it',async()=>{
  const fixture=await reviewFixture(); await reviewTime(61);
  assert.deepEqual((await new AuthorizationState(database).state(issuer,fixture.owner.sub)).roles,[]);
  assert.equal((await reviewDecision(fixture)).status,409);
  const expired=await api('GET',roleReviewPath+'/'+fixture.review.id,fixture.reviewer); assert.equal(expired.body.state,'expired');
  const retired=await api('POST',`${roleReviewPath}/policies/${fixture.policy.id}/retire`,fixture.manager,{ reason:'Reviewed retirement must not restore late rights',acknowledgeDeadlines:true },{ 'If-Match':`"od-role-review-policy:${fixture.policy.id}:1"` }); assert.equal(retired.status,200);
  const replacement=await api('POST',roleReviewPath+'/policies',fixture.manager,{ role:'license-manager',intervalSeconds:7200,windowSeconds:120,reviewerUserIds:[fixture.reviewer.userId],reason:'New policy cannot restamp an expired grant',acknowledgeDeadlines:true }); assert.equal(replacement.status,201);
  assert.deepEqual((await new AuthorizationState(database).state(issuer,fixture.owner.sub)).roles,[]);
  assert.equal((await database.query('SELECT policy_id FROM identity_role_review_leases WHERE id=$1',[fixture.review.id])).rows[0].policy_id,fixture.policy.id);
});
test('a retired policy leaves an accepted deadline binding until an independent timely retain explicitly closes recurrence',async()=>{
  const fixture=await reviewFixture();
  assert.equal((await api('POST',`${roleReviewPath}/policies/${fixture.policy.id}/retire`,fixture.manager,{ reason:'Independent reviewed policy retirement',acknowledgeDeadlines:true },{ 'If-Match':`"od-role-review-policy:${fixture.policy.id}:1"` })).status,200);
  const pending=await api('GET',roleReviewPath+'/'+fixture.review.id,fixture.reviewer); assert.equal(pending.body.state,'pending'); assert.equal(pending.body.policyRetired,true);
  assert.equal((await reviewDecision(fixture)).status,412); fixture.review=pending.body;
  const retained=await reviewDecision(fixture); assert.equal(retained.body.state,'exempt'); assert.equal(retained.body.deadlineAt,null);
  await reviewTime(31536000); assert.deepEqual((await new AuthorizationState(database).state(issuer,fixture.owner.sub)).roles,['license-manager']);
});
test('replacing a live review policy changes the named authority without extending the earlier cutoff',async()=>{
  const fixture=await reviewFixture(); const reviewer=await pimPrincipal('access-reviewer'); await reviewTime(10);
  assert.equal((await api('POST',`${roleReviewPath}/policies/${fixture.policy.id}/retire`,fixture.manager,{ reason:'Reviewed independent reviewer rotation',acknowledgeDeadlines:true },{ 'If-Match':`"od-role-review-policy:${fixture.policy.id}:1"` })).status,200);
  const replacement=await api('POST',roleReviewPath+'/policies',fixture.manager,{ role:'license-manager',intervalSeconds:7200,windowSeconds:120,reviewerUserIds:[reviewer.userId],reason:'Replacement with a different reviewed operator',acknowledgeDeadlines:true }); assert.equal(replacement.status,201);
  const current=await api('GET',roleReviewPath+'/'+fixture.review.id,reviewer); assert.equal(current.body.deadlineAt,fixture.review.deadlineAt); assert.equal(current.body.version,'2');
  assert.equal((await reviewDecision(fixture)).status,404);
  assert.equal((await reviewDecision({ ...fixture,reviewer })).status,412);
});
test('review revocation changes the actual canonical grant and audit instead of only a review label',async()=>{
  const fixture=await reviewFixture(); const denied=await reviewDecision(fixture,'revoke'); assert.equal(denied.status,200,JSON.stringify(denied.body)); assert.equal(denied.body.state,'denied');
  const grant=(await database.query('SELECT * FROM identity_role_assignments WHERE id=$1',[fixture.review.targetId])).rows[0]; assert.ok(grant.revoked_at);
  assert.deepEqual((await new AuthorizationState(database).state(issuer,fixture.owner.sub)).roles,[]);
  const audit=(await database.query("SELECT * FROM identity_role_review_audit WHERE lease_id=$1 AND action='revoke'",[fixture.review.id])).rows[0];
  assert.equal(JSON.parse(audit.actor).userId,fixture.reviewer.userId); assert.equal(audit.details.proof.factorRevision,'1');
});
test('reviewed eligibility expiry also withdraws a separately retained PIM lease and blocks new activation',async()=>{
  const fixture=await pimFixture(); const reviewer=await pimPrincipal('access-reviewer'); const manager=await pimPrincipal('access-review-administrator');
  assert.equal((await api('POST',roleReviewPath+'/policies',manager,{ role:'license-manager',intervalSeconds:3600,windowSeconds:60,reviewerUserIds:[reviewer.userId],reason:'Review active and eligible canonical privilege',acknowledgeDeadlines:true })).status,201);
  const requested=await pimRequest(fixture); assert.equal((await pimChange(requested.id,'approve',fixture.reviewer)).status,200); assert.equal((await pimChange(requested.id,'activate',fixture.owner)).body.status,'active');
  const queue=await api('GET',roleReviewPath+'/self',reviewer); const assignment=queue.body.reviews.find(row=>row.targetKind==='assignment'); assert.ok(assignment);
  assert.equal((await reviewDecision({ reviewer,review:assignment })).status,200);
  await reviewTime(61); const owner=await pimRefresh(fixture.owner);
  assert.deepEqual(owner.roles,['user']); const self=await api('GET',pimPath+'/self',owner); assert.equal(self.body.eligibilities[0].status,'expired'); assert.equal(self.body.requests[0].status,'expired');
  assert.equal((await api('POST',pimPath+'/requests',owner,{ ...fixture.body,id:randomUUID() })).status,409);
});
test('denying eligibility revokes its actual active assignments and pending requests transactionally',async()=>{
  const fixture=await pimFixture(); const requested=await pimRequest(fixture); await pimChange(requested.id,'approve',fixture.reviewer); await pimChange(requested.id,'activate',fixture.owner);
  const reviewer=await pimPrincipal('access-reviewer'); const manager=await pimPrincipal('access-review-administrator');
  assert.equal((await api('POST',roleReviewPath+'/policies',manager,{ role:'license-manager',intervalSeconds:3600,windowSeconds:60,reviewerUserIds:[reviewer.userId],reason:'Actual eligibility withdrawal through review',acknowledgeDeadlines:true })).status,201);
  const queue=await api('GET',roleReviewPath+'/self',reviewer); const review=queue.body.reviews.find(row=>row.targetKind==='eligibility');
  assert.equal((await reviewDecision({ reviewer,review },'revoke')).body.state,'denied');
  assert.ok((await database.query('SELECT revoked_at FROM identity_pim_eligibilities WHERE id=$1',[fixture.eligibility.id])).rows[0].revoked_at);
  assert.equal((await database.query('SELECT state FROM identity_pim_requests WHERE id=$1',[requested.id])).rows[0].state,'revoked');
});
test('new grants acquire review origins and no sole self-review path can bypass the policy',async()=>{
  const fixture=await reviewFixture(); const recipient=await pimPrincipal();
  await database.write('INSERT INTO identity_role_assignments(user_id,role,reason) VALUES($1,$2,$3)',[recipient.userId,'license-manager','New separately reviewed role entitlement'],'fixture');
  assert.equal((await api('GET',roleReviewPath+'/self',fixture.reviewer)).body.reviews.length,2);
  await assert.rejects(database.write('INSERT INTO identity_role_assignments(user_id,role,reason) VALUES($1,$2,$3)',[fixture.reviewer.userId,'license-manager','A sole reviewer cannot review their own grant'],'fixture'));
  const reader=await pimPrincipal('access-review-reader'); assert.equal((await api('GET',roleReviewPath+'/'+fixture.review.id,reader)).body.canDecide,false);
});
test('two independent decisions with one captured version have one winner and one retained-cycle audit',async()=>{
  const fixture=await reviewFixture(); const results=await Promise.all([reviewDecision(fixture),reviewDecision(fixture)]);
  assert.deepEqual(results.map(result=>result.status).sort(),[200,412]);
  assert.equal((await database.query("SELECT COUNT(*)::int AS count FROM identity_role_review_audit WHERE lease_id=$1 AND action='retain'",[fixture.review.id])).rows[0].count,1);
});
test('obsolete historical reviews cannot crowd a later effective grant out of the bounded open queue',async()=>{
  const fixture=await reviewFixture(); const stale=await identity(); const live=await identity();
  const deleted=await identity();
  await database.write("INSERT INTO identity_role_assignments(user_id,role,reason) VALUES($1,'license-manager','Retained review evidence for a removed user')",[deleted],'fixture');
  await database.write('DELETE FROM users WHERE id=$1',[deleted],'fixture');
  await database.write("INSERT INTO identity_role_assignments(user_id,role,reason,expires_at) SELECT $1,'license-manager','Short lived review queue fixture',clock_timestamp()+interval '1 second' FROM generate_series(1,100)",[stale],'fixture');
  await database.write("INSERT INTO identity_role_assignments(user_id,role,reason) VALUES($1,'license-manager','Later effective review queue fixture')",[live],'fixture');
  await new Promise(resolve=>setTimeout(resolve,1200));
  const queue=await api('GET',roleReviewPath+'/self',fixture.reviewer); assert.equal(queue.status,200); assert.equal(queue.body.truncated,true);
  assert.deepEqual(new Set(queue.body.reviews.slice(0,2).map(row=>row.userId)),new Set([fixture.owner.userId,live]));
  assert.ok(queue.body.reviews.slice(0,2).every(row=>row.state==='pending'));
});
test('review evidence failure rolls back an actual grant withdrawal and its source generation',async()=>{
  const fixture=await reviewFixture(); const before=await new AuthorizationState(database).state(issuer,fixture.owner.sub);
  await database.query("CREATE FUNCTION fail_review_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Review audit unavailable'; END $$");
  await database.query('CREATE TRIGGER fail_review_audit BEFORE INSERT ON identity_role_review_audit FOR EACH ROW EXECUTE FUNCTION fail_review_audit()');
  try { assert.equal((await reviewDecision(fixture,'revoke')).status,503); }
  finally { await database.query('DROP TRIGGER fail_review_audit ON identity_role_review_audit'); }
  assert.deepEqual(await new AuthorizationState(database).state(issuer,fixture.owner.sub),before);
  assert.equal((await database.query('SELECT version FROM identity_role_review_leases WHERE id=$1',[fixture.review.id])).rows[0].version,'1');
});
test('policy and lease evidence is immutable and reapplying the migration preserves a retained schedule',async()=>{
  const fixture=await reviewFixture(); const retained=await reviewDecision(fixture); assert.equal(retained.status,200);
  const before=(await database.query('SELECT * FROM identity_role_review_leases WHERE id=$1',[fixture.review.id])).rows[0];
  await assert.rejects(database.write('UPDATE identity_role_review_policies SET interval_seconds=7200,version=version+1 WHERE id=$1',[fixture.policy.id],'fixture'));
  await assert.rejects(database.query('DELETE FROM identity_role_review_leases WHERE id=$1',[fixture.review.id]));
  await assert.rejects(database.query("UPDATE identity_role_review_audit SET actor='forged'"));
  await database.query(fs.readFileSync(path.join(__dirname,'../../migrations/013_role_access_reviews.sql'),'utf8'));
  assert.deepEqual((await database.query('SELECT * FROM identity_role_review_leases WHERE id=$1',[fixture.review.id])).rows[0],before);
});
test('even a named current reviewer cannot self-certify or replace required bound MFA with flags',async()=>{
  const owner=await pimPrincipal('access-reviewer'); const reviewer=await pimPrincipal('access-reviewer'); const manager=await pimPrincipal('access-review-administrator');
  await database.write('INSERT INTO identity_role_assignments(user_id,role,reason) VALUES($1,$2,$3)',[owner.userId,'license-manager','Reviewed actual dual-duty operator'],'fixture');
  assert.equal((await api('POST',roleReviewPath+'/policies',manager,{ role:'license-manager',intervalSeconds:3600,windowSeconds:60,reviewerUserIds:[owner.userId,reviewer.userId].sort(),reason:'Independent peer review for a held role',acknowledgeDeadlines:true })).status,201);
  const current=await pimRefresh(owner); const queue=await api('GET',roleReviewPath+'/self',current); const review=queue.body.reviews.find(row=>row.userId===owner.userId);
  assert.equal(review.selfReview,true); assert.equal(review.canDecide,false);
  assert.equal((await reviewDecision({ reviewer:current,review })).status,403);
  assert.equal((await reviewDecision({ reviewer:{ ...reviewer,mfa_authorization:undefined },review })).status,428);
  assert.equal((await api('GET',roleReviewPath+'/policies/license-manager',{ ...manager,actor_type:'application' })).status,403);
  assert.equal((await reviewDecision({ reviewer,review })).status,200);
});
test('review authority revoked during a real role mutex wait cannot commit an admitted retain',async()=>{
  const fixture=await reviewFixture(); const lock=await database.pool.connect(); let changing;
  await lock.query('BEGIN'); await lock.query("SELECT pg_advisory_xact_lock(hashtextextended('od-role-reviews:license-manager',0))");
  try {
    changing=reviewDecision(fixture);
    for(let attempt=0;attempt<100;attempt++) {
      const waiting=await database.query("SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE '%od-role-reviews:%'");
      if(waiting.rows.length)break; if(attempt===99)throw new Error('No live review mutex waiter');
      await new Promise(resolve=>setTimeout(resolve,10));
    }
    await database.write("UPDATE identity_role_assignments SET revoked_at=clock_timestamp() WHERE user_id=$1 AND role='access-reviewer' AND revoked_at IS NULL",[fixture.reviewer.userId],'independent-security-operator');
    await lock.query('ROLLBACK'); assert.equal((await changing).status,401);
  } finally { await lock.query('ROLLBACK'); lock.release(); if(changing)await changing; }
  assert.equal((await database.query('SELECT version FROM identity_role_review_leases WHERE id=$1',[fixture.review.id])).rows[0].version,'1');
});
test('a final live-authority failure rolls back real review denial, canonical revocation and all evidence',async()=>{
  const fixture=await reviewFixture(); const { RoleReviews,reviewTag }=require('../RoleReviews'); let calls=0;
  const reviews=new RoleReviews(database,{ revalidate:async()=>{ if(++calls===2)throw Object.assign(new Error('Revoked actual session'),{ status:401 }); } });
  const before=await new AuthorizationState(database).state(issuer,fixture.owner.sub);
  await assert.rejects(reviews.decide(fixture.review.id,reviewTag(fixture.review),{ decision:'revoke',reason:'Final authority must roll back actual withdrawal',acknowledgeScope:true },{ ...fixture.reviewer,iss:issuer },'Bearer owned-fixture'),error=>error.status===401);
  assert.equal(calls,2); assert.deepEqual(await new AuthorizationState(database).state(issuer,fixture.owner.sub),before);
  assert.equal((await database.query('SELECT version FROM identity_role_review_leases WHERE id=$1',[fixture.review.id])).rows[0].version,'1');
  assert.equal((await database.query("SELECT COUNT(*)::int AS count FROM identity_role_review_audit WHERE lease_id=$1 AND action='revoke'",[fixture.review.id])).rows[0].count,0);
});
async function pimRefresh(principal) {
  const state = await new (require('../AuthorizationState').AuthorizationState)(database).state(issuer, principal.sub);
  const authTime = Math.floor(Date.now() / 1000);
  return { sub: principal.sub, userId: state.context.userId, actor_type: 'user', roles: state.roles, identity_authorization: state.context, auth_time: authTime, jti: randomUUID(), exp: authTime + 300,
    amr: ['pwd', 'otp'], mfa_authorization: { schemaVersion: 1, userId: state.context.userId, revision: '1', methods: ['pwd', 'otp'], authTime } };
}
async function pimFixture() {
  const manager = await pimPrincipal('pim-administrator'); const reviewer = await pimPrincipal('pim-approver'); const owner = await pimPrincipal();
  const eligibility = await api('POST', pimPath + '/eligibilities', manager, { userId: owner.userId, role: 'license-manager', maxDurationSeconds: 3600, validForSeconds: 86400, reason: 'Reviewed eligible license operator' });
  assert.equal(eligibility.status, 201);
  const body = { id: randomUUID(), eligibilityId: eligibility.body.id, durationSeconds: 3600, reason: 'Temporary license administration needed' };
  return { manager, reviewer, owner, eligibility: eligibility.body, body };
}
async function pimRequest(fixture) {
  const result = await api('POST', pimPath + '/requests', fixture.owner, fixture.body); assert.equal(result.status, 200); assert.equal(result.body.status, 'pending'); return result.body;
}

async function activationPolicy(role, principal, required = true, maxDurationSeconds = 600, reviewerUserIds = []) {
  const route = pimPath + '/policies/' + role;
  const before = await api('GET',route,principal); assert.equal(before.status,200);
  return api('PUT',route,principal,{ required,maxDurationSeconds,reviewerUserIds,reason:'Independent reviewed activation requirement',acknowledgeInvalidation:true },{ 'If-Match':activationEtag(role,before.body.version) });
}
async function restoreActivationPolicy(role) {
  await database.transaction(async client => {
    await client.query("SELECT set_config('opendirectory.activation_reason','Disposable fixture policy restoration',true)");
    await client.query('UPDATE identity_role_activation_policies SET activation_required=false,max_duration_seconds=28800,reviewer_user_ids=\'{}\',version=version+1 WHERE role=$1',[role]);
  },{ actor:'disposable-test-owner' });
}
test('activation policy catalog, immutable origins, protected duties and migration reapplication are durable', async () => {
  const roles = require('../../../../../packages/directory-role-contract').ROLES;
  const catalog = (await database.query('SELECT role FROM identity_role_activation_policies ORDER BY role COLLATE "C"')).rows.map(row => row.role);
  assert.deepEqual(catalog,[...roles].sort());
  const manager = await pimPrincipal('privileged-access-policy-administrator');
  const changed = await activationPolicy('license-manager',manager); assert.equal(changed.status,200);
  try {
    await database.query(fs.readFileSync(path.join(__dirname,'../../migrations/012_privileged_access_policy.sql'),'utf8'));
    const current = await api('GET',pimPath+'/policies/license-manager',manager); assert.deepEqual(current.body,changed.body);
    await assert.rejects(database.write('UPDATE identity_role_activation_policies SET version=version+1 WHERE role=$1',['license-manager'],'fixture'));
    await assert.rejects(database.query('DELETE FROM identity_role_activation_policies WHERE role=$1',['license-manager']));
    await assert.rejects(database.query('UPDATE identity_role_activation_audit SET actor=$1',['forged']));
    await assert.rejects(database.write("UPDATE identity_role_authentication SET version=version+1,mfa_required=false WHERE role='privileged-access-policy-administrator'",[],'fixture'));
  } finally { await restoreActivationPolicy('license-manager'); }
});
test('policy readers and policy operators have no assignment, eligibility, review or profile authority', async () => {
  const manager = await pimPrincipal('privileged-access-policy-administrator'); const reader = await pimPrincipal('privileged-access-policy-reader');
  const target = await identity(); const route = pimPath+'/policies/license-reader';
  const viewed = await api('GET',route,reader); assert.equal(viewed.status,200); assert.equal(viewed.body.canManage,false);
  for (const principal of [reader,manager]) {
    assert.equal((await api('GET','/api/users',principal)).status,403);
    assert.equal((await api('POST','/api/users/'+target+'/roles',principal,{ role:'license-manager',durationSeconds:600,reason:'No duty escalation is allowed' })).status,403);
    assert.equal((await api('POST',pimPath+'/eligibilities',principal,{})).status,403);
    assert.equal((await api('GET',pimPath+'/requests',principal)).status,403);
  }
  assert.equal((await api('GET',route+'?actor=admin',reader)).status,400);
  assert.equal((await api('PUT',route,reader,{})).status,403);
  assert.equal((await api('PUT',route,{ ...manager,mfa_authorization:undefined },{ required:true,maxDurationSeconds:600,reason:'No invented factor is accepted',acknowledgeInvalidation:true },{ 'If-Match':activationEtag('license-reader','1') })).status,428);
});
test('mandatory PIM removes existing direct authority and neither role managers nor global administrators can bypass it', async () => {
  const owner = await pimPrincipal('license-manager'); const manager = await pimPrincipal('privileged-access-policy-administrator'); const global = await pimPrincipal('admin');
  const before = await new AuthorizationState(database).state(issuer,owner.sub);
  assert.equal((await activationPolicy('license-manager',manager)).status,200);
  try {
    const after = await new AuthorizationState(database).state(issuer,owner.sub);
    assert.deepEqual(after.roles,[]); assert.equal(after.context.revision,before.context.revision); assert.notEqual(after.context.rolesRevision,before.context.rolesRevision);
    const listed = await api('GET','/api/users/'+owner.userId+'/roles',global); assert.equal(listed.body.assignments[0].status,'policy_changed');
    const directCatalog = await api('GET','/api/identity/roles/catalog',global); assert.equal(directCatalog.body.roles.find(role => role.role==='license-manager').assignable,false);
    const activationCatalog = await api('GET',pimPath+'/catalog',owner); assert.equal(activationCatalog.body.roles.find(role => role.role==='license-manager').maxDurationSeconds,600);
    assert.equal((await api('POST','/api/users/'+owner.userId+'/roles',global,{ role:'license-manager',durationSeconds:600,reason:'A global role is not an exception' })).status,409);
    await assert.rejects(database.write('INSERT INTO identity_role_assignments(user_id,role,reason) VALUES($1,$2,$3)',[owner.userId,'license-manager','Offline direct bypass is also forbidden'],'fixture'));
  } finally { await restoreActivationPolicy('license-manager'); }
  assert.deepEqual((await new AuthorizationState(database).state(issuer,owner.sub)).roles,[]);
});
test('relaxing a policy does not resurrect old direct grants but a new reviewed assignment works', async () => {
  const owner = await pimPrincipal('license-manager'); const manager = await pimPrincipal('privileged-access-policy-administrator');
  assert.equal((await activationPolicy('license-manager',manager)).status,200); await restoreActivationPolicy('license-manager');
  assert.deepEqual((await new AuthorizationState(database).state(issuer,owner.sub)).roles,[]);
  const global = await pimPrincipal('admin'); const created = await api('POST','/api/users/'+owner.userId+'/roles',global,{ role:'license-manager',durationSeconds:600,reason:'New independently reviewed direct grant' });
  assert.equal(created.status,201); assert.deepEqual((await new AuthorizationState(database).state(issuer,owner.sub)).roles,['license-manager']);
});
test('current policy bounds PIM requests and activation still requires independent approval and fresh MFA', async () => {
  const manager = await pimPrincipal('privileged-access-policy-administrator'); assert.equal((await activationPolicy('license-manager',manager)).status,200);
  try {
    const fixture = await pimFixture();
    assert.equal((await api('POST',pimPath+'/requests',fixture.owner,fixture.body)).status,409);
    fixture.body.durationSeconds = 600; const request = await pimRequest(fixture);
    assert.equal((await pimChange(request.id,'approve',fixture.owner)).status,403);
    assert.equal((await pimChange(request.id,'approve',fixture.reviewer)).body.status,'approved');
    assert.equal((await pimChange(request.id,'activate',{ ...fixture.owner,mfa_authorization:undefined })).status,428);
    const active = await pimChange(request.id,'activate',fixture.owner); assert.equal(active.body.status,'active');
    assert.deepEqual((await new AuthorizationState(database).state(issuer,fixture.owner.sub)).roles,['license-manager','user']);
    const grant = (await database.query('SELECT * FROM identity_role_assignments WHERE activation_request_id=$1',[request.id])).rows[0];
    const policy = (await database.query("SELECT * FROM identity_role_activation_policies WHERE role='license-manager'")).rows[0];
    assert.equal(grant.policy_version,policy.version); assert.ok(new Date(grant.expires_at)-new Date(grant.created_at)<=600000);
  } finally { await restoreActivationPolicy('license-manager'); }
});
test('policy edits stale pending, approved and active requests without reviving them on later relaxation', async () => {
  const manager = await pimPrincipal('privileged-access-policy-administrator');
  const fixtures = [await pimFixture(),await pimFixture(),await pimFixture()];
  const requests = await Promise.all(fixtures.map(pimRequest));
  for (const index of [1,2]) assert.equal((await pimChange(requests[index].id,'approve',fixtures[index].reviewer)).body.status,'approved');
  assert.equal((await pimChange(requests[2].id,'activate',fixtures[2].owner)).body.status,'active');
  assert.equal((await activationPolicy('license-manager',manager)).status,200);
  try {
    for (const [index,fixture] of fixtures.entries()) {
      const self = await api('GET',pimPath+'/self',await pimRefresh(fixture.owner)); assert.equal(self.body.requests[0].status,'stale');
      assert.equal((await pimChange(requests[index].id,'activate',await pimRefresh(fixture.owner))).status,409);
    }
    fixtures[0].body = { ...fixtures[0].body,id:randomUUID(),durationSeconds:600 };
    assert.equal((await pimRequest(fixtures[0])).status,'pending');
  } finally { await restoreActivationPolicy('license-manager'); }
  assert.deepEqual((await new AuthorizationState(database).state(issuer,fixtures[2].owner.sub)).roles,['user']);
});
test('assignment and request policy origins cannot be rewritten or supplied to bypass a rule', async () => {
  const fixture = await pimFixture(); const request = await pimRequest(fixture);
  await assert.rejects(database.write('UPDATE identity_pim_requests SET policy_version=policy_version+1 WHERE id=$1',[request.id],'fixture'));
  const grant = (await database.query('SELECT id FROM identity_role_assignments WHERE user_id=$1',[fixture.owner.userId])).rows[0];
  await assert.rejects(database.write('UPDATE identity_role_assignments SET policy_version=policy_version+1 WHERE id=$1',[grant.id],'fixture'));
  const manager = await pimPrincipal('privileged-access-policy-administrator'); assert.equal((await activationPolicy('license-manager',manager)).status,200);
  try {
    await assert.rejects(database.write("UPDATE identity_pim_requests SET state='approved',decision_authority=$2 WHERE id=$1",[request.id,JSON.stringify({ userId:fixture.reviewer.userId })],'fixture'));
  } finally { await restoreActivationPolicy('license-manager'); }
});
test('concurrent conditional policy writers have one winner and one immutable evidence record', async () => {
  const manager = await pimPrincipal('privileged-access-policy-administrator'); const role = 'license-reader';
  const route = pimPath+'/policies/'+role; const before = await api('GET',route,manager);
  const input = { required:true,maxDurationSeconds:600,reason:'Concurrent reviewed activation policy',acknowledgeInvalidation:true };
  try {
    const results = await Promise.all([api('PUT',route,manager,input,{ 'If-Match':activationEtag(role,before.body.version) }),api('PUT',route,manager,input,{ 'If-Match':activationEtag(role,before.body.version) })]);
    assert.deepEqual(results.map(result => result.status).sort(),[200,412]);
    const audit = (await database.query('SELECT * FROM identity_role_activation_audit WHERE role=$1 AND current->>\'version\'=$2',[role,String(BigInt(before.body.version)+1n)])).rows;
    assert.equal(audit.length,1); assert.equal(JSON.parse(audit[0].actor).userId,manager.userId); assert.equal(audit[0].reason,input.reason);
  } finally { await restoreActivationPolicy(role); }
});
test('policy audit failure rolls back the version and leaves previous real grants effective', async () => {
  const owner = await pimPrincipal('license-manager'); const manager = await pimPrincipal('privileged-access-policy-administrator');
  const before = await new AuthorizationState(database).state(issuer,owner.sub);
  await database.query("CREATE FUNCTION reject_activation_evidence() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture audit unavailable'; END $$");
  await database.query('CREATE TRIGGER reject_activation_evidence BEFORE INSERT ON identity_role_activation_audit FOR EACH ROW EXECUTE FUNCTION reject_activation_evidence()');
  try { assert.equal((await activationPolicy('license-manager',manager)).status,503); }
  finally { await database.query('DROP TRIGGER reject_activation_evidence ON identity_role_activation_audit'); }
  assert.deepEqual(await new AuthorizationState(database).state(issuer,owner.sub),before);
});
test('a policy actor revoked during a real row-lock wait cannot commit using admission-time proof', async () => {
  const manager = { ...await pimPrincipal('privileged-access-policy-administrator'),iss:issuer };
  const store = new PrivilegedAccessPolicy(database,{ revalidate:async () => {} }); const role = 'license-manager';
  const before = await store.get(role,manager); const lock = await database.pool.connect();
  await lock.query('BEGIN'); await lock.query('SELECT * FROM identity_role_activation_policies WHERE role=$1 FOR UPDATE',[role]);
  const changing = store.change(role,activationEtag(role,before.version),{ required:true,maxDurationSeconds:600,reason:'Independent actor revocation during wait',acknowledgeInvalidation:true },manager);
  const rejected = assert.rejects(changing,error => error.status===401);
  try {
    for (let attempt=0;attempt<100;attempt++) {
      const waiting = await database.query("SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'SELECT * FROM identity_role_activation_policies WHERE role=%FOR UPDATE%'");
      if (waiting.rows.length) break;
      if (attempt===99) throw new Error('No live policy waiter observed');
      await new Promise(resolve => setTimeout(resolve,10));
    }
    await database.write('UPDATE identity_role_assignments SET revoked_at=clock_timestamp() WHERE user_id=$1',[manager.userId],'independent-reviewer');
  } finally { await lock.query('ROLLBACK'); lock.release(); }
  await rejected;
  assert.equal((await database.query('SELECT version FROM identity_role_activation_policies WHERE role=$1',[role])).rows[0].version,before.version);
});
test('a live-authority failure after real policy DML rolls back its audit and effective-right change', async () => {
  const manager = { ...await pimPrincipal('privileged-access-policy-administrator'),iss:issuer }; const owner = await pimPrincipal('license-manager'); let calls=0;
  const store = new PrivilegedAccessPolicy(database,{ revalidate:async () => { if (++calls===2) throw Object.assign(new Error('Session independently revoked'),{ status:401 }); } });
  const before = await store.get('license-manager',manager); const state = await new AuthorizationState(database).state(issuer,owner.sub);
  await assert.rejects(store.change(before.role,activationEtag(before.role,before.version),{ required:true,maxDurationSeconds:600,reason:'Real final authority failure rolls back',acknowledgeInvalidation:true },manager),error => error.status===401);
  assert.equal(calls,2); assert.deepEqual(await new AuthorizationState(database).state(issuer,owner.sub),state);
  assert.equal((await store.get(before.role,manager)).version,before.version);
});
test('global administration has no implicit exception and a named independent approver can bootstrap a current bounded admin lease', async () => {
  const global = await pimPrincipal('admin'); const before = await new AuthorizationState(database).state(issuer,global.sub);
  const reviewer=await pimPrincipal('pim-approver'); const owner=await pimPrincipal();
  assert.equal((await activationPolicy('admin',global,true,600,[reviewer.userId])).status,409);
  const eligible=await api('POST',pimPath+'/eligibilities',global,{ userId:owner.userId,role:'admin',maxDurationSeconds:600,validForSeconds:86400,reason:'Independent eligible global administration' }); assert.equal(eligible.status,201);
  assert.equal((await activationPolicy('admin',global)).status,400);
  const changed = await activationPolicy('admin',global,true,600,[reviewer.userId]); assert.equal(changed.status,200);
  try {
    assert.deepEqual((await new AuthorizationState(database).state(issuer,global.sub)).roles,[]);
    const { bootstrapRole } = require('../../scripts/bootstrap-role');
    await assert.rejects(bootstrapRole(database,{ userId:global.userId,role:'admin',duration:null,reason:'An offline grant is not a policy bypass' }));
    const requested=await api('POST',pimPath+'/requests',owner,{ id:randomUUID(),eligibilityId:eligible.body.id,durationSeconds:600,reason:'Current global administrator activation' }); assert.equal(requested.status,200);
    const stranger=await pimPrincipal('pim-approver'); assert.equal((await pimChange(requested.body.id,'approve',stranger)).status,403);
    assert.equal((await pimChange(requested.body.id,'approve',{ ...reviewer,mfa_authorization:undefined })).status,428);
    assert.equal((await pimChange(requested.body.id,'approve',reviewer)).body.status,'approved');
    assert.equal((await pimChange(requested.body.id,'activate',owner)).body.status,'active');
    assert.ok((await new AuthorizationState(database).state(issuer,owner.sub)).roles.includes('admin'));
  } finally { await restoreActivationPolicy('admin'); }
  const after = await new AuthorizationState(database).state(issuer,global.sub);
  assert.deepEqual(after.roles,[]); assert.notEqual(after.context.rolesRevision,before.context.rolesRevision);
});
test('a direct grant racing policy enforcement commits only an old origin that immediately loses authority', async () => {
  const manager = await pimPrincipal('privileged-access-policy-administrator'); const owner = await pimPrincipal();
  const writer = await database.pool.connect(); let changing;
  await writer.query('BEGIN');
  await writer.query('INSERT INTO identity_role_assignments(user_id,role,reason) VALUES($1,$2,$3)',[owner.userId,'license-manager','Racing reviewed direct grant fixture']);
  try {
    changing = activationPolicy('license-manager',manager);
    for(let attempt=0;attempt<100;attempt++) {
      const waiting=await database.query("SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'SELECT * FROM identity_role_activation_policies WHERE role=%FOR UPDATE%'");
      if(waiting.rows.length)break;
      if(attempt===99)throw new Error('No actual policy writer blocked by the direct grant');
      await new Promise(resolve=>setTimeout(resolve,10));
    }
    await writer.query('COMMIT'); assert.equal((await changing).status,200);
    assert.deepEqual((await new AuthorizationState(database).state(issuer,owner.sub)).roles,['user']);
  } finally {
    await writer.query('ROLLBACK'); writer.release(); if(changing)await changing;
    await restoreActivationPolicy('license-manager');
  }
});
test('retained policy-invalidated evidence does not overflow effective grants or prevent a new reviewed role', async () => {
  const manager = await pimPrincipal('privileged-access-policy-administrator'); const target = await identity(); const global = await pimPrincipal('admin');
  await database.write("INSERT INTO identity_role_assignments(user_id,role,reason) SELECT $1,'license-manager','Retained old policy origin fixture' FROM generate_series(1,100)",[target],'fixture');
  assert.equal((await activationPolicy('license-manager',manager)).status,200); await restoreActivationPolicy('license-manager');
  const created = await api('POST','/api/users/'+target+'/roles',global,{ role:'license-manager',durationSeconds:600,reason:'New effective grant after stale evidence' }); assert.equal(created.status,201);
  const roles = await require('../RoleState').readRoleState(database,target); assert.deepEqual(roles.roles,['license-manager']);
  assert.equal((await database.query('SELECT COUNT(*)::int AS count FROM identity_role_assignments WHERE user_id=$1',[target])).rows[0].count,101);
});
const pimChange = (id, action, principal) => api('POST', `${pimPath}/requests/${id}/${action}`, principal, {});

test('PIM eligibility grants no runtime role and its administrator has no profile, active-role or review authority', async () => {
  const fixture = await pimFixture();
  assert.equal((await database.query("SELECT COUNT(*)::int AS count FROM identity_role_assignments WHERE user_id=$1 AND role='license-manager'", [fixture.owner.userId])).rows[0].count, 0);
  for (const route of ['/api/users', `/api/users/${fixture.owner.userId}/roles`, pimPath + '/requests']) assert.equal((await api('GET', route, fixture.manager)).status, 403);
  const self = await api('GET', pimPath + '/self', fixture.owner); assert.equal(self.body.eligibilities.length, 1); assert.equal(self.body.eligibilities[0].status, 'eligible');
  assert.equal((await api('POST', pimPath + '/eligibilities', fixture.manager, { userId: fixture.manager.userId })).status, 403);
  assert.equal((await api('POST', pimPath + '/eligibilities', fixture.manager, { userId: fixture.owner.userId, role: 'admin', maxDurationSeconds: 3600, validForSeconds: 86400, reason: 'Protected role must need global review' })).status, 403);
});
test('PIM requests are canonical self-service, reject injected beneficiaries, and retry one immutable UUID without duplication', async () => {
  const fixture = await pimFixture(); const request = await pimRequest(fixture);
  assert.equal((await api('POST', pimPath + '/requests', fixture.owner, fixture.body)).body.id, request.id);
  assert.equal((await database.query('SELECT COUNT(*)::int AS count FROM identity_pim_audit WHERE entity_id=$1', [request.id])).rows[0].count, 1);
  assert.equal((await api('POST', pimPath + '/requests', fixture.owner, { ...fixture.body, reason: 'Different request cannot reuse ID' })).status, 409);
  assert.equal((await api('POST', pimPath + '/requests', fixture.reviewer, { ...fixture.body, id: randomUUID() })).status, 404);
  assert.equal((await api('POST', pimPath + '/requests', fixture.owner, { ...fixture.body, userId: fixture.reviewer.userId })).status, 400);
  assert.equal((await pimChange(request.id, 'activate', fixture.owner)).status, 409);
  assert.equal((await pimChange(request.id, 'cancel', fixture.reviewer)).status, 404);
  assert.equal((await api('GET', pimPath + '/self?userId=' + fixture.owner.userId, fixture.reviewer)).status, 400);
});
test('independent approval alone grants no access; only the fresh authenticated owner can activate a bounded canonical lease', async () => {
  const fixture = await pimFixture(); const request = await pimRequest(fixture);
  await database.write("INSERT INTO identity_role_assignments(user_id,role,reason) VALUES($1,'pim-approver','Disposable self-approval denial fixture')", [fixture.owner.userId], 'fixture');
  const ownReviewer = await pimRefresh(fixture.owner);
  assert.equal((await pimChange(request.id, 'approve', { ...ownReviewer, sub: 'another-alias' })).status, 401);
  assert.equal((await pimChange(request.id, 'approve', ownReviewer)).status, 403);
  assert.equal((await pimChange(request.id, 'approve', fixture.reviewer)).status, 409);
  assert.equal((await pimChange(request.id, 'cancel', ownReviewer)).status, 200);
  fixture.owner = ownReviewer; fixture.body.id = randomUUID(); const next = await pimRequest(fixture);
  assert.equal((await pimChange(next.id, 'approve', fixture.reviewer)).body.status, 'approved');
  assert.equal((await database.query("SELECT COUNT(*)::int AS count FROM identity_role_assignments WHERE user_id=$1 AND role='license-manager'", [fixture.owner.userId])).rows[0].count, 0);
  assert.equal((await pimChange(next.id, 'activate', fixture.reviewer)).status, 404);
  assert.equal((await pimChange(next.id, 'activate', { ...ownReviewer, auth_time: Math.floor(Date.now() / 1000) - 301 })).status, 428);
  for (const unproven of [
    { ...ownReviewer, amr: ['pwd'] },
    { ...ownReviewer, mfa_authorization: undefined, mfaEnabled: true },
    { ...ownReviewer, mfa_authorization: { ...ownReviewer.mfa_authorization, userId: randomUUID() } },
    { ...ownReviewer, mfa_authorization: { ...ownReviewer.mfa_authorization, authTime: ownReviewer.auth_time - 1 } },
  ]) assert.equal((await pimChange(next.id, 'activate', unproven)).status, 428);
  const active = await pimChange(next.id, 'activate', ownReviewer); assert.equal(active.status, 200); assert.equal(active.body.status, 'active'); assert.ok(active.body.assignmentId);
  assert.ok(new Date(active.body.expiresAt) <= new Date(fixture.eligibility.expiresAt));
  const refreshed = await pimRefresh(fixture.owner); assert.equal((await pimChange(next.id, 'activate', refreshed)).body.assignmentId, active.body.assignmentId);
  assert.equal((await database.query('SELECT COUNT(*)::int AS count FROM identity_role_assignments WHERE activation_request_id=$1', [next.id])).rows[0].count, 1);
});
test('concurrent PIM decisions have one winner and cannot create two role leases', async () => {
  const fixture = await pimFixture(); const request = await pimRequest(fixture); const second = await pimPrincipal('pim-approver');
  const decisions = await Promise.all([fixture.reviewer, second].map(reviewer => pimChange(request.id, 'approve', reviewer)));
  assert.deepEqual(decisions.map(result => result.status).sort(), [200, 409]);
  const activations = await Promise.all([1, 2].map(() => pimChange(request.id, 'activate', fixture.owner)));
  assert.deepEqual(activations.map(result => result.status).sort(), [200, 409]);
  assert.equal((await database.query('SELECT COUNT(*)::int AS count FROM identity_role_assignments WHERE activation_request_id=$1', [request.id])).rows[0].count, 1);
});
test('PIM audit failure rolls back approval, activation and the target authorization generation', async () => {
  const fixture = await pimFixture(); const request = await pimRequest(fixture);
  await database.query('ALTER TABLE identity_pim_audit RENAME TO unavailable_pim_audit');
  try { assert.equal((await pimChange(request.id, 'approve', fixture.reviewer)).status, 503); }
  finally { await database.query('ALTER TABLE unavailable_pim_audit RENAME TO identity_pim_audit'); }
  assert.equal((await pimChange(request.id, 'approve', fixture.reviewer)).status, 200);
  await database.query('ALTER TABLE identity_pim_audit RENAME TO unavailable_pim_audit');
  try {
    assert.equal((await pimChange(request.id, 'activate', fixture.owner)).status, 503);
    assert.equal((await database.query('SELECT COUNT(*)::int AS count FROM identity_role_assignments WHERE activation_request_id=$1', [request.id])).rows[0].count, 0);
    assert.equal((await pimRefresh(fixture.owner)).identity_authorization.revision, fixture.owner.identity_authorization.revision);
  } finally { await database.query('ALTER TABLE unavailable_pim_audit RENAME TO identity_pim_audit'); }
  assert.equal((await pimChange(request.id, 'activate', fixture.owner)).body.status, 'active');
});
test('eligibility revocation atomically revokes canonical leases, is nonresurrectable and preserves audit evidence', async () => {
  const fixture = await pimFixture(); const request = await pimRequest(fixture); await pimChange(request.id, 'approve', fixture.reviewer);
  const active = await pimChange(request.id, 'activate', fixture.owner); assert.equal(active.body.status, 'active');
  assert.equal((await api('DELETE', `${pimPath}/eligibilities/${fixture.eligibility.id}`, fixture.manager)).status, 200);
  const assignment = (await database.query('SELECT revoked_at FROM identity_role_assignments WHERE id=$1', [active.body.assignmentId])).rows[0]; assert.ok(assignment.revoked_at);
  const updated = await pimRefresh(fixture.owner); assert.equal((await api('GET', pimPath + '/self', updated)).body.requests[0].status, 'revoked');
  await assert.rejects(database.query('UPDATE identity_pim_eligibilities SET revoked_at=NULL WHERE id=$1', [fixture.eligibility.id]), error => error.code === '23514');
  await assert.rejects(database.query("UPDATE identity_pim_requests SET state='approved' WHERE id=$1", [request.id]), error => error.code === '23514');
  await assert.rejects(database.query('DELETE FROM identity_pim_audit WHERE entity_id=$1', [request.id]), /append-only/);
});
test('approval authority is rechecked at activation and cannot survive reviewer disablement or role reset', async () => {
  const fixture = await pimFixture(); const request = await pimRequest(fixture); await pimChange(request.id, 'approve', fixture.reviewer);
  await database.write('UPDATE users SET authorization_revision=authorization_revision+1 WHERE id=$1', [fixture.reviewer.userId], 'security-reset');
  assert.equal((await pimChange(request.id, 'activate', fixture.owner)).status, 409);
  assert.equal((await database.query('SELECT COUNT(*)::int AS count FROM identity_role_assignments WHERE activation_request_id=$1', [request.id])).rows[0].count, 0);
  const original = (await database.query('SELECT * FROM identity_pim_requests WHERE id=$1', [request.id])).rows[0];
  await database.query(fs.readFileSync(path.join(__dirname, '../../migrations/008_privileged_activation.sql'), 'utf8'));
  assert.deepEqual((await database.query('SELECT * FROM identity_pim_requests WHERE id=$1', [request.id])).rows[0], original);
});

test('PIM activation also fences requester and reviewer role expiry when their user revision has not changed', async () => {
  for (const subject of ['requester', 'reviewer']) {
    const fixture = await pimFixture();
    if (subject === 'reviewer') fixture.reviewer = await pimPrincipal();
    const principal = subject === 'requester' ? fixture.owner : fixture.reviewer;
    const role = subject === 'requester' ? 'directory-reader' : 'pim-approver';
    await database.write("INSERT INTO identity_role_assignments(user_id,role,reason,expires_at) VALUES($1,$2,'Disposable role-expiry edge fixture',clock_timestamp()+interval '2 seconds')", [principal.userId, role], 'fixture');
    if (subject === 'requester') fixture.owner = await pimRefresh(principal); else fixture.reviewer = await pimRefresh(principal);
    const request = await pimRequest(fixture); assert.equal((await pimChange(request.id, 'approve', fixture.reviewer)).status, 200);
    const revision = (subject === 'requester' ? fixture.owner : fixture.reviewer).identity_authorization.revision;
    await new Promise(resolve => setTimeout(resolve, 2100));
    assert.equal((await database.query('SELECT authorization_revision FROM users WHERE id=$1', [principal.userId])).rows[0].authorization_revision, revision);
    const owner = await pimRefresh(fixture.owner); assert.equal((await pimChange(request.id, 'activate', owner)).status, 409);
    if (subject === 'requester') assert.equal((await api('GET', pimPath + '/self', owner)).body.requests[0].status, 'stale');
    assert.equal((await database.query('SELECT COUNT(*)::int AS count FROM identity_role_assignments WHERE activation_request_id=$1', [request.id])).rows[0].count, 0);
  }
});
test('eligibility withdrawal rolls back its audit and all active-lease changes when role audit cannot commit', async () => {
  const fixture = await pimFixture(); const request = await pimRequest(fixture); await pimChange(request.id, 'approve', fixture.reviewer); const active = await pimChange(request.id, 'activate', fixture.owner);
  const before = (await database.query('SELECT authorization_revision FROM users WHERE id=$1', [fixture.owner.userId])).rows[0];
  await database.query('ALTER TABLE identity_role_audit RENAME TO unavailable_role_audit');
  try {
    assert.equal((await api('DELETE', `${pimPath}/eligibilities/${fixture.eligibility.id}`, fixture.manager)).status, 503);
    assert.equal((await database.query('SELECT revoked_at FROM identity_role_assignments WHERE id=$1', [active.body.assignmentId])).rows[0].revoked_at, null);
    assert.equal((await database.query('SELECT revoked_at FROM identity_pim_eligibilities WHERE id=$1', [fixture.eligibility.id])).rows[0].revoked_at, null);
    assert.deepEqual((await database.query('SELECT authorization_revision FROM users WHERE id=$1', [fixture.owner.userId])).rows[0], before);
  } finally { await database.query('ALTER TABLE unavailable_role_audit RENAME TO identity_role_audit'); }
  assert.equal((await api('DELETE', `${pimPath}/eligibilities/${fixture.eligibility.id}`, fixture.manager)).status, 200);
});
test('PIM snapshots and assignment origin cannot be edited to bypass pending approval or extend a lease', async () => {
  const fixture = await pimFixture(); const request = await pimRequest(fixture);
  await assert.rejects(database.query("UPDATE identity_pim_requests SET state='approved',decision_authority=$2 WHERE id=$1", [request.id,
    JSON.stringify({ ...fixture.owner.identity_authorization, userId: fixture.owner.userId.toUpperCase(), issuer, subject: fixture.owner.sub })]), error => error.code === '23514');
  await assert.rejects(database.write("INSERT INTO identity_role_assignments(user_id,role,reason,expires_at,activation_request_id) VALUES($1,'license-manager','Unapproved SQL fixture must be rejected',clock_timestamp()+interval '1 hour',$2)", [fixture.owner.userId, request.id], 'fixture'), error => error.code === '23514');
  for (const sql of ["UPDATE identity_pim_requests SET state='active' WHERE id=$1", "UPDATE identity_pim_requests SET deadline_at=clock_timestamp()+interval '1 year' WHERE id=$1", "UPDATE identity_pim_requests SET request_authority='{}'::jsonb WHERE id=$1"]) {
    await assert.rejects(database.query(sql, [request.id]), error => error.code === '23514');
  }
  assert.equal((await pimChange(request.id, 'approve', fixture.reviewer)).status, 200); const active = await pimChange(request.id, 'activate', fixture.owner);
  await assert.rejects(database.query('UPDATE identity_role_assignments SET activation_request_id=NULL WHERE id=$1', [active.body.assignmentId]), error => error.code === '23514');
  await assert.rejects(database.query('UPDATE identity_pim_requests SET decided_at=clock_timestamp() WHERE id=$1', [request.id]), error => error.code === '23514');
});

test('policy administration has its own fixed real-MFA catalog policy and cannot weaken it with raw updates', async () => {
  const rows = (await database.query("SELECT role,mfa_required,max_age_seconds FROM identity_role_authentication WHERE role IN('policy-reader','policy-administrator') ORDER BY role")).rows;
  assert.deepEqual(rows, [{ role: 'policy-administrator', mfa_required: true, max_age_seconds: 300 }, { role: 'policy-reader', mfa_required: false, max_age_seconds: 3600 }]);
  await assert.rejects(database.query("UPDATE identity_role_authentication SET mfa_required=false,version=version+1 WHERE role='policy-administrator'"), error => error.code === '23514');
});

test('policy-role migration replay preserves existing policy generations and creates no human role grants', async () => {
  const before = (await database.query("SELECT * FROM identity_role_authentication WHERE role IN('policy-reader','policy-administrator') ORDER BY role")).rows;
  const assignments = (await database.query('SELECT count(*)::int AS count FROM identity_role_assignments')).rows[0].count;
  await database.query(fs.readFileSync(path.join(__dirname, '../../migrations/022_policy_operation_roles.sql'), 'utf8'));
  assert.deepEqual((await database.query("SELECT * FROM identity_role_authentication WHERE role IN('policy-reader','policy-administrator') ORDER BY role")).rows, before);
  assert.equal((await database.query('SELECT count(*)::int AS count FROM identity_role_assignments')).rows[0].count, assignments);
});
test('publication review is a separate fixed-MFA protected role and migration replay does not appoint any reviewer',async()=>{
 const before=(await database.query("SELECT * FROM identity_role_authentication WHERE role='policy-publication-reviewer'")).rows;assert.equal(before.length,1);assert.equal(before[0].mfa_required,true);assert.equal(before[0].max_age_seconds,300);
 const assignments=(await database.query('SELECT count(*)::int AS count FROM identity_role_assignments')).rows[0].count;
 for(const sql of ["UPDATE identity_role_authentication SET mfa_required=false WHERE role='policy-publication-reviewer'","DELETE FROM identity_role_authentication WHERE role='policy-publication-reviewer'"])await assert.rejects(database.query(sql),error=>error.code==='23514');
 await database.query(fs.readFileSync(path.join(__dirname,'../../migrations/023_policy_publication_roles.sql'),'utf8'));assert.deepEqual((await database.query("SELECT * FROM identity_role_authentication WHERE role='policy-publication-reviewer'")).rows,before);assert.equal((await database.query('SELECT count(*)::int AS count FROM identity_role_assignments')).rows[0].count,assignments);
});
test('actual publication actor snapshots bind separate reviewer grants, user and issuer-link incarnations without administrator review substitution',async()=>{
 const {PolicyPublicationActorSnapshotStore}=require('../PolicyPublicationActorSnapshotStore');const source=new PolicyPublicationActorSnapshotStore(database);
 for(const role of ['admin','policy-administrator']){const author=await pimPrincipal(role);const observed=await source.snapshot(author.userId,issuer);assert.ok(observed.requestRevision);assert.equal(observed.reviewRevision,null);}
 const voter=await pimPrincipal('policy-publication-reviewer');const initial=await source.snapshot(voter.userId,issuer);assert.ok(initial.reviewRevision);assert.equal(initial.requestRevision,null);
 await database.write("UPDATE identity_role_assignments SET revoked_at=clock_timestamp() WHERE user_id=$1 AND role='policy-publication-reviewer' AND revoked_at IS NULL",[voter.userId],'owned-reviewer-withdrawal');assert.equal((await source.snapshot(voter.userId,issuer)).reviewRevision,null);
 await database.write("INSERT INTO identity_role_assignments(user_id,role,reason) VALUES($1,'policy-publication-reviewer','Explicit new reviewer incarnation')",[voter.userId],'owned-reviewer-reissue');const reissued=await source.snapshot(voter.userId,issuer);assert.notEqual(reissued.reviewRevision,initial.reviewRevision);
 await database.write('UPDATE users SET enabled=false WHERE id=$1',[voter.userId],'owned-reviewer-disable');assert.equal((await source.snapshot(voter.userId,issuer)).reviewRevision,null);await database.write('UPDATE users SET enabled=true WHERE id=$1',[voter.userId],'owned-reviewer-enable');assert.notEqual((await source.snapshot(voter.userId,issuer)).reviewRevision,reissued.reviewRevision);
 const beforeReset=await source.snapshot(voter.userId,issuer);await new AuthorizationState(database).invalidate(voter.userId,'owned-publication-security-reset');assert.notEqual((await source.snapshot(voter.userId,issuer)).reviewRevision,beforeReset.reviewRevision);
});

test('denial and owner cancellation remain terminal, and an owner can deactivate their own actual lease', async () => {
  const fixture = await pimFixture(); const denied = await pimRequest(fixture);
  const decision = await pimChange(denied.id, 'deny', fixture.reviewer); assert.equal(decision.status, 200); assert.equal(decision.body.status, 'denied');
  assert.equal(decision.body.decidedBy, fixture.reviewer.userId); assert.equal(decision.body.approvalExpiresAt, null);
  assert.equal((await pimChange(denied.id, 'activate', fixture.owner)).status, 409); assert.equal((await pimChange(denied.id, 'approve', fixture.reviewer)).status, 409);
  fixture.body.id = randomUUID(); const cancelled = await pimRequest(fixture); assert.equal((await pimChange(cancelled.id, 'cancel', fixture.owner)).body.status, 'cancelled');
  assert.equal((await pimChange(cancelled.id, 'approve', fixture.reviewer)).status, 409);
  fixture.body.id = randomUUID(); const pending = await pimRequest(fixture); await pimChange(pending.id, 'approve', fixture.reviewer);
  const active = await pimChange(pending.id, 'activate', fixture.owner); assert.equal(active.body.status, 'active');
  const owner = await pimRefresh(fixture.owner); assert.equal((await pimChange(pending.id, 'cancel', owner)).body.status, 'revoked');
  assert.ok((await database.query('SELECT revoked_at FROM identity_role_assignments WHERE id=$1', [active.body.assignmentId])).rows[0].revoked_at);
});
