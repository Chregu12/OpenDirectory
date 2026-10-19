'use strict';

const { test,before,beforeEach,after }=require('node:test');
const assert=require('node:assert/strict'); const { randomUUID,createHash }=require('node:crypto'); const fs=require('node:fs'); const path=require('node:path'); const {Pool}=require('pg');
const {LicenseAllocator}=require('../LicenseAllocator'); const {GroupLicenseAllocator}=require('../GroupLicenseAllocator');
const {LicenseDelegations,tag}=require('../LicenseDelegations'); const {LicenseGrants,etag}=require('../LicenseGrants');
const {LicenseScopeActivations,eligibilityTag,activationTag}=require('../LicenseScopeActivations');
const {LicenseScopePolicies,policyTag}=require('../LicenseScopePolicies');
const {LicenseScopeReviews,policyTag:scopeReviewPolicyTag,reviewTag:scopeReviewTag}=require('../LicenseScopeReviews');
const {LicenseReviews,reviewTag:licenseReviewTag}=require('../LicenseReviews');
const {getLicensePermissions}=require('../../middleware/licenseAccess');
const{groupSnapshot}=require('../../../../../../scripts/lib/group-license-snapshot-fixture.cjs');
const schema='delegations_'+randomUUID().replaceAll('-','');const admin=new Pool({connectionString:process.env.LICENSE_TEST_DATABASE_URL,max:1});
let scopeReviews;let reviewAdmin;let scopeVoter;let pool;let allocator;let groups;let store;let pim;let policies;let policyAdmin;let reviewer;let owner;let delegate;let beneficiary;let manager;let fault;let validations;const people=new Map();const teams=new Map();
function actor(role){const userId=randomUUID();const authTime=Math.floor(Date.now()/1000);const principal={userId,issuer:'https://scopes.test',subject:userId,enabled:true};
 const user={iss:principal.issuer,sub:userId,actor_type:'user',roles:[role],identity_authorization:{userId,revision:'1',linkRevision:'1',rolesRevision:'a'.repeat(64)},auth_time:authTime,amr:['pwd','otp'],mfa_authorization:{schemaVersion:1,userId,revision:'1',authTime,methods:['pwd','otp']}};
 people.set(userId,{role,revision:'1',enabled:true,fingerprint:createHash('sha256').update(randomUUID()).digest('hex')});return{user,principal,authorization:'Bearer '+userId};}
const source={scopeReviewer:async userId=>({schemaVersion:1,userId,enabled:people.get(userId)?.enabled===true,linked:people.has(userId),canReview:people.get(userId)?.enabled===true&&(people.get(userId)?.role==='license-delegation-reviewer'||people.get(userId)?.scopeReview===true)}),activationReviewer:async userId=>({schemaVersion:1,userId,enabled:people.get(userId)?.enabled===true,linked:people.has(userId),revision:people.get(userId)?.revision||'1',reviewRevision:people.get(userId)?.role==='license-scope-activation-reviewer'&&people.get(userId)?.enabled===true?people.get(userId).fingerprint:null}),user:async userId=>({schemaVersion:1,userId,revision:people.get(userId)?.revision||'1',enabled:people.get(userId)?.enabled===true,deleted:!people.has(userId)}),
 delegate:async userId=>{const person=people.get(userId);return{schemaVersion:1,userId,revision:person?.revision||'1',enabled:person?.enabled===true,linked:!!person,delegationRevision:person?.role==='license-delegate'&&person.enabled?person.fingerprint:null};},
 snapshot:async(groupId,authorization)=>groupSnapshot({groupId,name:'Scoped team',revision:teams.get(groupId).revision,memberIds:teams.get(groupId).members,viewerUserId:authorization.slice(7),viewerEnabled:true},{revisions:Object.fromEntries([...people].map(([userId,person])=>[userId,person.revision||'1']))})};
before(async()=>{await admin.query('CREATE SCHEMA '+schema);pool=new Pool({connectionString:process.env.LICENSE_TEST_DATABASE_URL,max:12,options:`-c search_path=${schema},public`});
 for(const name of fs.readdirSync(path.join(__dirname,'../../db/migrations')).filter(name=>/^(00[4-9]|01[0-7]|02[0-2])_.*\.sql$/.test(name)).sort())await pool.query(fs.readFileSync(path.join(__dirname,'../../db/migrations',name),'utf8'));
 allocator=new LicenseAllocator({query:(...args)=>pool.query(...args),getClient:()=>pool.connect()},{source});groups=new GroupLicenseAllocator({allocator,source});store=new LicenseDelegations(allocator,{source,revalidate:async()=>{validations++;if(fault)await fault(validations);}});pim=new LicenseScopeActivations(allocator,{delegations:store});policies=new LicenseScopePolicies(allocator,{delegations:store});scopeReviews=new LicenseScopeReviews(allocator,{delegations:store});});
beforeEach(async()=>{await pool.query('TRUNCATE license_scope_audit,license_scope_grants,license_review_audit,license_review_leases,license_review_policies,license_grant_events,license_grants,license_catalog,license_subjects,license_requests,license_audit_events CASCADE');
 await pool.query('CREATE OR REPLACE FUNCTION license_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp(); $$');people.clear();teams.clear();fault=null;validations=0;owner=actor('license-scope-administrator');delegate=actor('license-delegate');beneficiary=actor('user');manager=actor('license-manager');reviewer=actor('license-scope-activation-reviewer');policyAdmin=actor('license-scope-policy-administrator');reviewAdmin=actor('license-delegation-review-administrator');scopeVoter=actor('license-delegation-reviewer');});
after(async()=>{await pool.end();await admin.query('DROP SCHEMA '+schema+' CASCADE');await admin.end();});
async function product(){return(await pool.query("INSERT INTO license_catalog(name,total_seats) VALUES('Scoped pool',5) RETURNING *")).rows[0];}
async function grant(license,duty='allocator',who=delegate){return store.create({licenseId:license.id,userId:who.principal.userId,duty,durationSeconds:60,reason:'Explicit independent bounded pool delegation',confirm:true},owner.user,owner.principal,owner.authorization);}
async function run(license,permission,operation,who=delegate){return store.run(license.id,permission,permission.endsWith('.read')?null:'Explicit scoped operation confirmation',who.user,who.principal,who.authorization,operation);}
async function assign(license,who=delegate,target=beneficiary){return run(license,'assignments.manage',()=>allocator.assign(license.id,{assignee_type:'user',assignee_id:target.principal.userId},who.principal.userId,who),who);}

test('legacy governance rejects injected company-owned parent rows before any authoritative source call',async()=>{
 const license=await product();const scope=await grant(license);await assign(license);
 const grants=new LicenseGrants(allocator,{revalidate:async()=>{}});const direct=(await grants.list(license.id)).grants[0];
 const voter=actor('license-reviewer');const configurator=actor('license-review-administrator');
 const reviews=new LicenseReviews(allocator,{source,revalidate:async()=>{}});
 source.reviewer=async userId=>({canReview:userId===voter.principal.userId});
 const policy=await reviews.create({licenseId:license.id,intervalSeconds:3600,windowSeconds:60,reviewerUserIds:[voter.principal.userId],reason:'Controlled legacy review isolation fixture',acknowledgeDeadlines:true},configurator.user,configurator.principal,configurator.authorization);
 const eligible=await pim.create({licenseId:license.id,userId:delegate.principal.userId,duty:'reader',durationSeconds:3600,maxDurationSeconds:60,reviewerUserIds:[reviewer.principal.userId],reason:'Controlled legacy activation isolation fixture',confirm:true},owner.user,owner.principal,owner.authorization);
 const client=await pool.connect();
 try{await client.query('BEGIN');await client.query('ALTER TABLE license_catalog DISABLE TRIGGER USER');await client.query('UPDATE license_catalog SET business_tenant_id=$2,business_revision=1 WHERE id=$1',[license.id,randomUUID()]);await client.query('ALTER TABLE license_catalog ENABLE TRIGGER USER');await client.query('COMMIT');}
 catch(error){await client.query('ROLLBACK');throw error;}finally{client.release();}
 try{
 const retained=(await pool.query('SELECT (SELECT count(*) FROM license_assignments)::text AS assignments,(SELECT count(*) FROM license_grant_events)::text AS events,(SELECT count(*) FROM license_scope_audit)::text AS audit')).rows[0];
 const original={...source};let calls=0;for(const name of Object.keys(source))source[name]=async()=>{calls++;throw new Error('Company pool reached a legacy source');};
 try{
  const reason={reason:'Controlled cross-namespace rejection check',confirm:true};
  for(const operation of [
   ()=>store.list(license.id,undefined,owner.user,owner.principal),
   ()=>store.revoke(scope.id,tag(scope),reason,owner.user,owner.principal,owner.authorization),
   ()=>store.create({licenseId:license.id,userId:delegate.principal.userId,duty:'reader',durationSeconds:60,...reason},owner.user,owner.principal,owner.authorization),
   ()=>run(license,'pool.read',()=>{}),
   ()=>grants.list(license.id),()=>grants.get(license.id,direct.id),
   ()=>grants.revoke(license.id,direct.id,etag(direct),reason,manager.user,manager.principal,manager.authorization),
   ()=>pim.peek(eligible.id),()=>pim.list(license.id,undefined,owner.user,owner.principal),
   ()=>policies.get(license.id,'allocator',policyAdmin.user,policyAdmin.principal),
   ()=>scopeReviews.policy(license.id,'allocator','grant',reviewAdmin.user,reviewAdmin.principal),
   ()=>reviews.policy(license.id,configurator.user,configurator.principal),
   ()=>reviews.retire(policy.id,`"od-license-review-policy:${policy.id}:${policy.version}"`,{reason:reason.reason,acknowledgeDeadlines:true},configurator.user,configurator.principal,configurator.authorization),
   ()=>groups.assign(license.id,{assignee_id:randomUUID()},manager.principal.userId,manager),
   ()=>groups.reconcile(license.id,randomUUID(),manager.principal.userId,manager),
  ])await assert.rejects(operation,error=>error.status===404);
  assert.equal(calls,0);
 }finally{for(const name of Object.keys(source))if(!Object.hasOwn(original,name))delete source[name];Object.assign(source,original);delete source.reviewer;}
 assert.deepEqual((await pool.query('SELECT (SELECT count(*) FROM license_assignments)::text AS assignments,(SELECT count(*) FROM license_grant_events)::text AS events,(SELECT count(*) FROM license_scope_audit)::text AS audit')).rows[0],retained);
 }finally{
  const cleanup=await pool.connect();try{await cleanup.query('BEGIN');await cleanup.query('ALTER TABLE license_catalog DISABLE TRIGGER USER');await cleanup.query('UPDATE license_catalog SET business_tenant_id=NULL,business_revision=NULL WHERE id=$1',[license.id]);await cleanup.query('ALTER TABLE license_catalog ENABLE TRIGGER USER');await cleanup.query('COMMIT');}catch(error){await cleanup.query('ROLLBACK');throw error;}finally{cleanup.release();}
 }
});
test('a delegate has no global license permissions and an explicit lease is necessary',async()=>{const license=await product();assert.deepEqual(getLicensePermissions(delegate.user),['licenses.delegations.self']);
 await assert.rejects(assign(license),error=>error.status===404);await grant(license);await assign(license);assert.equal((await pool.query('SELECT used_seats FROM license_catalog')).rows[0].used_seats,1);
 assert.equal((await pool.query("SELECT COUNT(*)::int AS count FROM license_scope_audit WHERE action='use'")).rows[0].count,1);});
test('neither another pool nor a reader operation can authorize mutation, even with an additional global role',async()=>{const first=await product();const other=await product();await grant(first,'reader');
 await assert.rejects(assign(first),error=>error.status===404);await assert.rejects(assign(other),error=>error.status===404);
 delegate.user.roles.push('license-manager');await assert.rejects(run(first,'pool.read',()=>allocator.assign(first.id,{assignee_type:'user',assignee_id:beneficiary.principal.userId},delegate.principal.userId,delegate)),error=>error.status===403);
 await assert.rejects(run(first,'pool.read',()=>store.read(other.id,()=>{},delegate.principal.userId)),error=>error.status===403);assert.equal((await pool.query('SELECT COUNT(*)::int AS count FROM license_assignments')).rows[0].count,0);});
test('write assurance comes from the operation rather than an optional reason or a caller-selected read wrapper',async()=>{const license=await product();await grant(license);
 await assert.rejects(store.run(license.id,'assignments.manage',null,delegate.user,delegate.principal,delegate.authorization,()=>{}),error=>error.status===400);
 await assert.rejects(store.run(license.id,'assignments.manage','Explicit independent allocation',{...delegate.user,amr:['pwd']},delegate.principal,delegate.authorization,()=>{}),error=>error.status===428);
 const approver=actor('license-delegate');await grant(license,'approver',approver);await assert.rejects(run(license,'requests.review',()=>allocator.assign(license.id,{assignee_type:'user',assignee_id:beneficiary.principal.userId},approver.principal.userId,approver),approver),error=>error.status===403);
 assert.equal((await pool.query('SELECT COUNT(*)::int AS count FROM license_assignments')).rows[0].count,0);});
test('SQL scope guards reject raw reader writes and cross-pool writes without trusting controller routing',async()=>{const first=await product();const other=await product();await grant(first,'reader');
 await assert.rejects(run(first,'pool.read',()=>store.read(first.id,client=>client.query('UPDATE license_catalog SET total_seats=99 WHERE id=$1',[first.id]),delegate.principal.userId)),error=>error.code==='42501');
 const lease=(await store.list(first.id,undefined,owner.user,owner.principal)).delegations[0];await store.revoke(lease.id,tag(lease),{reason:'Replace read authority with explicit allocation duty',confirm:true},owner.user,owner.principal,owner.authorization);await grant(first,'allocator');
 await assert.rejects(run(first,'assignments.manage',()=>store.read(first.id,client=>client.query('UPDATE license_catalog SET used_seats=0 WHERE id=$1',[other.id]),delegate.principal.userId)),error=>error.code==='42501');
 assert.equal((await pool.query('SELECT total_seats FROM license_catalog WHERE id=$1',[first.id])).rows[0].total_seats,5);});
test('conditional source withdrawal is usable only through the exact allocator scope and preserves a group overlap',async()=>{const license=await product();await grant(license);await assign(license);
 const groupId=randomUUID();teams.set(groupId,{revision:'1',members:[beneficiary.principal.userId]});await allocator.assign(license.id,{assignee_type:'group',assignee_id:groupId},manager.principal.userId,manager);
 const grants=new LicenseGrants(allocator,{revalidate:async()=>{}});const direct=(await grants.list(license.id)).grants.find(row=>row.kind==='direct');
 const result=await run(license,'assignments.manage',()=>grants.revoke(license.id,direct.id,etag(direct),{confirm:true,reason:'Withdraw only this exact scoped direct source'},delegate.user,delegate.principal,delegate.authorization));
 assert.equal(result.usersRetainingAssignment,1);assert.equal((await pool.query('SELECT used_seats FROM license_catalog')).rows[0].used_seats,1);});
test('delegations are immutable, bounded, independent and do not revive when expired',async()=>{const license=await product();const lease=await grant(license);
 await assert.rejects(grant(license),error=>error.code==='23505');await assert.rejects(pool.query('UPDATE license_scope_grants SET expires_at=expires_at+interval \'1 hour\''),error=>error.code==='42501');
 await assert.rejects(pool.query('DELETE FROM license_scope_grants'),error=>error.code==='42501');await assert.rejects(pool.query('UPDATE license_scope_audit SET reason=\'forged reason\''),error=>error.code==='42501');
 await pool.query("CREATE OR REPLACE FUNCTION license_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+interval '61 seconds'; $$");await assert.rejects(assign(license),error=>error.status===404);
 const revoked=await store.revoke(lease.id,tag(lease),{confirm:true,reason:'Retire the expired delegation incarnation'},owner.user,owner.principal,owner.authorization);assert.equal(revoked.state,'revoked');
 const replacement=await grant(license);assert.notEqual(replacement.id,lease.id);await assert.rejects(store.revoke(lease.id,tag(lease),{confirm:true,reason:'Old conditional version must remain fenced'},owner.user,owner.principal,owner.authorization),error=>error.status===412);});
test('beneficiary lifecycle and delegate-role incarnation changes invalidate the lease permanently',async()=>{const license=await product();await grant(license);people.get(delegate.principal.userId).revision='3';
 assert.equal((await store.self(delegate.user,delegate.principal,delegate.authorization)).delegations.length,0);await assert.rejects(assign(license),error=>error.status===404);
 people.get(delegate.principal.userId).revision='1';people.get(delegate.principal.userId).fingerprint='b'.repeat(64);await assert.rejects(assign(license),error=>error.status===404);});
test('control-plane roles cannot self-delegate and allocator duties do not imply request approval',async()=>{const license=await product();people.get(owner.principal.userId).role='license-delegate';
 await assert.rejects(grant(license,'allocator',owner),error=>error.status===400);await grant(license);
 await assert.rejects(run(license,'requests.review',async()=>{}),error=>error.status===404);await assert.rejects(store.create({licenseId:license.id,userId:beneficiary.principal.userId,duty:'reader',durationSeconds:60,reason:'No implicit scope administration power',confirm:true},manager.user,manager.principal,manager.authorization),error=>error.status===403);});
test('the approver scope retains canonical self-beneficiary restrictions',async()=>{const license=await product();await grant(license,'approver');
 const requested=await allocator.request(license.id,{requester_id:beneficiary.principal.userId,assignee_type:'user',assignee_id:delegate.principal.userId},beneficiary);
 await assert.rejects(run(license,'requests.review',()=>allocator.review(requested.record.id,delegate.principal.userId,'approved',delegate)),error=>error.status===403);
 assert.equal((await pool.query('SELECT status FROM license_requests')).rows[0].status,'pending');});
test('an independent approver can allocate only requests from the captured pool',async()=>{const license=await product();const other=await product();await grant(license,'approver');const requester=actor('user');
 const request=async poolId=>allocator.request(poolId,{requester_id:requester.principal.userId,assignee_type:'user',assignee_id:requester.principal.userId},requester);
 const current=await request(license.id);const foreign=await request(other.id);await run(license,'requests.review',()=>allocator.review(current.record.id,delegate.principal.userId,'approved',delegate));
 await assert.rejects(run(license,'requests.review',()=>allocator.review(foreign.record.id,delegate.principal.userId,'approved',delegate)),error=>error.status===403);
 assert.equal((await pool.query('SELECT status FROM license_requests WHERE id=$1',[foreign.record.id])).rows[0].status,'pending');assert.equal((await pool.query('SELECT used_seats FROM license_catalog WHERE id=$1',[license.id])).rows[0].used_seats,1);});
test('joining a benefiting group during scoped approval cannot commit the earlier snapshot',async()=>{const license=await product();await grant(license,'approver');const groupId=randomUUID();teams.set(groupId,{revision:'1',members:[beneficiary.principal.userId]});
 const current=await allocator.request(license.id,{requester_id:beneficiary.principal.userId,assignee_type:'group',assignee_id:groupId},beneficiary);validations=0;
 fault=async count=>{if(count===1){teams.get(groupId).members.push(delegate.principal.userId);teams.get(groupId).revision='2';}};
 await assert.rejects(run(license,'requests.review',()=>allocator.review(current.record.id,delegate.principal.userId,'approved',delegate)),error=>error.status===403);
 assert.equal((await pool.query('SELECT status FROM license_requests WHERE id=$1',[current.record.id])).rows[0].status,'pending');assert.equal((await pool.query('SELECT COUNT(*)::int AS count FROM license_assignments')).rows[0].count,0);});
test('post-DML issuer loss rolls back scoped rights, capacity and use evidence atomically',async()=>{const license=await product();await grant(license);validations=0;fault=async count=>{if(count===2)throw Object.assign(new Error('Owned revoked session'),{status:401});};
 await assert.rejects(assign(license),error=>error.status===401);assert.equal((await pool.query('SELECT used_seats FROM license_catalog')).rows[0].used_seats,0);
 assert.equal((await pool.query("SELECT COUNT(*)::int AS count FROM license_scope_audit WHERE action='use'")).rows[0].count,0);assert.equal((await pool.query('SELECT COUNT(*)::int AS count FROM license_assignment_sources')).rows[0].count,0);});
test('a scoped disabled-target check cannot offboard assignments in another pool',async()=>{const first=await product();const other=await product();await allocator.assign(other.id,{assignee_type:'user',assignee_id:beneficiary.principal.userId},manager.principal.userId,manager);await grant(first);
 people.get(beneficiary.principal.userId).enabled=false;people.get(beneficiary.principal.userId).revision='2';await assert.rejects(assign(first),error=>error.status===403);
 assert.equal((await pool.query('SELECT used_seats FROM license_catalog WHERE id=$1',[other.id])).rows[0].used_seats,1);assert.equal((await pool.query('SELECT directory_enabled FROM license_subjects WHERE user_id=$1',[beneficiary.principal.userId])).rows[0].directory_enabled,true);});
test('a lease expiring during the final issuer check rolls back the source and its use audit',async()=>{const license=await product();await grant(license);validations=0;
 fault=async count=>{if(count===2)await pool.query("CREATE OR REPLACE FUNCTION license_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+interval '61 seconds'; $$");};
 await assert.rejects(assign(license),error=>error.status===403);assert.equal((await pool.query('SELECT COUNT(*)::int AS count FROM license_assignment_sources')).rows[0].count,0);
 assert.equal((await pool.query("SELECT COUNT(*)::int AS count FROM license_scope_audit WHERE action='use'")).rows[0].count,0);});
test('a lease expiring during a pool-lock wait cannot commit an admitted allocation',async()=>{const license=await product();await grant(license);const blocker=await pool.connect();let pending;
 try{await blocker.query('BEGIN');await blocker.query('SELECT id FROM license_catalog WHERE id=$1 FOR UPDATE',[license.id]);pending=assign(license);pending.catch(()=>{});let waiting=false;
  for(let attempt=0;attempt<200;attempt++){waiting=(await pool.query("SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'SELECT * FROM license_catalog WHERE id = %'")).rows.length>0;if(waiting)break;await new Promise(resolve=>setTimeout(resolve,10));}assert.equal(waiting,true);
  await blocker.query("CREATE OR REPLACE FUNCTION license_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+interval '61 seconds'; $$");await blocker.query('COMMIT');await assert.rejects(pending,error=>error.status===403);
  assert.equal((await pool.query('SELECT COUNT(*)::int AS count FROM license_assignments')).rows[0].count,0);
 }finally{await blocker.query('ROLLBACK');blocker.release();if(pending)await pending.catch(()=>{});}});

const confirmation={reason:'Independent canonical scope activation confirmation',confirm:true};
async function eligible(license,extra={}){return pim.create({licenseId:license.id,userId:delegate.principal.userId,duty:'allocator',durationSeconds:3600,maxDurationSeconds:300,reviewerUserIds:[reviewer.principal.userId],...confirmation,...extra},owner.user,owner.principal,owner.authorization);}
async function requested(eligibility,durationSeconds=60){return pim.request(eligibility.id,eligibilityTag(eligibility),{durationSeconds,...confirmation},delegate.user,delegate.principal,delegate.authorization);}
async function transition(request,action,who=delegate,body=confirmation){return pim.transition(request.id,activationTag(request),body,action,who.user,who.principal,who.authorization);}
async function approved(eligibility){return transition(await requested(eligibility),'decide',reviewer,{decision:'approved',...confirmation});}
test('pool eligibility and approval grant no authority until the owner performs a fresh explicit activation',async()=>{
 const license=await product();const foreign=await product();const eligibility=await eligible(license);await assert.rejects(assign(license),error=>error.status===404);
 const request=await requested(eligibility);assert.equal(request.status,'pending');assert.equal((await pim.assigned(reviewer.user,reviewer.principal)).requests[0].canReview,true);
 const approvedRequest=await transition(request,'decide',reviewer,{decision:'approved',...confirmation});await assert.rejects(assign(license),error=>error.status===404);
 const active=await transition(approvedRequest,'activate');assert.equal(active.status,'activated');assert.ok(active.grantId);await assign(license);await assert.rejects(assign(foreign),error=>error.status===404);
 assert.deepEqual(getLicensePermissions(delegate.user),['licenses.delegations.self']);assert.equal((await store.self(delegate.user,delegate.principal,delegate.authorization)).delegations.length,1);
 const inactive=await transition(active,'deactivate');assert.equal(inactive.status,'deactivated');await assert.rejects(assign(license),error=>error.status===404);
 assert.equal((await pool.query('SELECT used_seats FROM license_catalog WHERE id=$1',[license.id])).rows[0].used_seats,1);
 const next=await transition(await approved(eligibility),'activate');assert.notEqual(next.grantId,active.grantId);
 const original=(await pool.query('SELECT * FROM license_scope_grants WHERE id=$1',[next.grantId])).rows[0];
 await pool.query(fs.readFileSync(path.join(__dirname,'../../db/migrations/015_license_delegation_reviews.sql'),'utf8'));
 assert.deepEqual((await pool.query('SELECT * FROM license_scope_grants WHERE id=$1',[next.grantId])).rows[0],original);assert.equal((await pool.query('SELECT license_scope_grant_usable($1) AS usable',[next.grantId])).rows[0].usable,true);
});
test('named activation reviewers are a separate protected duty without implicit global allocation or self approval',async()=>{
 const license=await product();await assert.rejects(eligible(license,{reviewerUserIds:[owner.principal.userId]}),error=>error.status===400);
 await assert.rejects(eligible(license,{reviewerUserIds:[delegate.principal.userId]}),error=>error.status===400);
 await assert.rejects(eligible(license,{reviewerUserIds:[manager.principal.userId]}),error=>error.status===409);
 const eligibility=await eligible(license);const request=await requested(eligibility);delegate.user.roles.push('license-scope-activation-reviewer');
 await assert.rejects(transition(request,'decide',delegate,{decision:'approved',...confirmation}),error=>error.status===403);
 const root=actor('admin');await assert.rejects(pim.assigned(root.user,root.principal),error=>error.status===403);
 const foreignIssuer={...reviewer,principal:{...reviewer.principal,issuer:'https://foreign.test'},user:{...reviewer.user,iss:'https://foreign.test'}};await assert.rejects(transition(request,'decide',foreignIssuer,{decision:'approved',...confirmation}),error=>error.status===403);
 await assert.rejects(transition(request,'activate',reviewer),error=>error.status===403);assert.deepEqual(getLicensePermissions(reviewer.user),['licenses.scopepim.review']);
});
test('scope activation commands require exact versions, real fresh MFA and independent one-way transitions',async()=>{
 const license=await product();const eligibility=await eligible(license);const request=await requested(eligibility);
 await assert.rejects(pim.request(eligibility.id,null,{durationSeconds:60,...confirmation},delegate.user,delegate.principal,delegate.authorization),error=>error.status===428);
 await assert.rejects(transition(request,'activate'),error=>error.status===409);
 await assert.rejects(pim.transition(request.id,activationTag(request),{decision:'approved',...confirmation},'decide',{...reviewer.user,amr:['pwd']},reviewer.principal,reviewer.authorization),error=>error.status===428);
 const votes=await Promise.allSettled([transition(request,'decide',reviewer,{decision:'approved',...confirmation}),transition(request,'decide',reviewer,{decision:'denied',...confirmation})]);assert.equal(votes.filter(result=>result.status==='fulfilled').length,1);assert.equal(votes.find(result=>result.status==='rejected').reason.status,412);
 await assert.rejects(transition(request,'cancel'),error=>error.status===412);
});
test('an unanswered or approved activation request cannot activate after its response deadline',async()=>{
 const license=await product();const eligibility=await eligible(license);const request=await approved(eligibility);
 await pool.query("CREATE OR REPLACE FUNCTION license_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+interval '901 seconds'; $$");
 await assert.rejects(transition(request,'activate'),error=>error.status===409);assert.equal((await pim.self(delegate.user,delegate.principal,delegate.authorization)).requests[0].canActivate,false);
 const cancelled=await transition(request,'cancel');assert.equal(cancelled.status,'cancelled');assert.equal((await requested(eligibility)).status,'pending');
});
test('eligibility revocation immediately fences an active scope lease but preserves already allocated seats',async()=>{
 const license=await product();const eligibility=await eligible(license);const active=await transition(await approved(eligibility),'activate');await assign(license);
 await pim.revoke(eligibility.id,eligibilityTag(eligibility),confirmation,owner.user,owner.principal,owner.authorization);
 assert.equal((await store.self(delegate.user,delegate.principal,delegate.authorization)).delegations.length,0);await assert.rejects(assign(license),error=>error.status===404);
 assert.equal((await pool.query('SELECT used_seats FROM license_catalog WHERE id=$1',[license.id])).rows[0].used_seats,1);
 await transition(active,'deactivate');const replacement=await eligible(license);assert.notEqual(replacement.id,eligibility.id);await transition(await approved(replacement),'activate');
});
test('canonical disable/reactivate and delegate role incarnations permanently stale the eligibility origin',async()=>{
 const license=await product();const eligibility=await eligible(license);const request=await approved(eligibility);people.get(delegate.principal.userId).revision='3';
 await assert.rejects(transition(request,'activate'),error=>error.status===409);assert.equal((await pim.self(delegate.user,delegate.principal,delegate.authorization)).eligibilities[0].state,'stale');
 people.get(delegate.principal.userId).revision='1';people.get(delegate.principal.userId).fingerprint='f'.repeat(64);await assert.rejects(transition(request,'activate'),error=>error.status===409);
});
test('activation SQL retains origins and cannot fabricate self authority without an approved independent request',async()=>{
 const license=await product();const eligibility=await eligible(license);const request=await requested(eligibility);
 await assert.rejects(pool.query('UPDATE license_scope_eligibilities SET expires_at=expires_at+interval \'1 hour\' WHERE id=$1',[eligibility.id]),error=>error.code==='42501');
 await assert.rejects(pool.query('UPDATE license_scope_activation_requests SET status=\'activated\' WHERE id=$1',[request.id]),error=>error.code==='42501');
 await assert.rejects(pool.query('DELETE FROM license_scope_pim_audit'),error=>error.code==='42501');
 const client=await pool.connect();try{await client.query('BEGIN');await store.context(client,confirmation,delegate.user,delegate.principal);await client.query("SELECT set_config('opendirectory.scope_pim_action','activate',true)");
  await assert.rejects(client.query(`INSERT INTO license_scope_grants(license_id,user_id,issuer,duty,eligibility_revision,delegation_revision,activation_request_id,expires_at) VALUES($1,$2,$3,'allocator','1',$4,$5,license_now()+interval '60 seconds')`,[license.id,delegate.principal.userId,delegate.principal.issuer,people.get(delegate.principal.userId).fingerprint,request.id]),error=>error.code==='42501');
 }finally{await client.query('ROLLBACK');client.release();}
});
test('resource callbacks cannot edit eligibility or fabricate activation control evidence',async()=>{
 const license=await product();await grant(license);const eligibility=await eligible(license);delegate.user.roles.push('license-scope-administrator');
 await assert.rejects(run(license,'assignments.manage',()=>pim.revoke(eligibility.id,eligibilityTag(eligibility),confirmation,delegate.user,delegate.principal,delegate.authorization)),error=>error.status===403);
 await assert.rejects(run(license,'assignments.manage',()=>store.read(license.id,client=>client.query("INSERT INTO license_scope_pim_audit(eligibility_id,actor,reason,action,details) VALUES($1,'{}','Forged control proof','activate','{}')",[eligibility.id]),delegate.principal.userId)),error=>error.code==='42501');
});
test('activation consumes approval once and parallel activation cannot issue two live grants',async()=>{
 const license=await product();const request=await approved(await eligible(license));const results=await Promise.allSettled([transition(request,'activate'),transition(request,'activate')]);
 assert.equal(results.filter(result=>result.status==='fulfilled').length,1);assert.equal(results.find(result=>result.status==='rejected').reason.status,412);
 assert.equal((await pool.query('SELECT count(*)::int AS count FROM license_scope_grants')).rows[0].count,1);
});
test('post-DML issuer withdrawal rolls back an activated lease, request consumption and both audit planes',async()=>{
 const license=await product();const request=await approved(await eligible(license));validations=0;fault=async count=>{if(count===2)throw Object.assign(new Error('Owned activation issuer loss'),{status:401});};
 await assert.rejects(transition(request,'activate'),error=>error.status===401);assert.equal((await pool.query('SELECT count(*)::int AS count FROM license_scope_grants')).rows[0].count,0);
 assert.equal((await pool.query('SELECT status FROM license_scope_activation_requests WHERE id=$1',[request.id])).rows[0].status,'approved');
 assert.equal((await pool.query("SELECT count(*)::int AS count FROM license_scope_pim_audit WHERE action='activate'")).rows[0].count,0);
});
test('a lease expiring inside the final issuer call cannot commit activation or spend approval',async()=>{
 const license=await product();const request=await approved(await eligible(license));validations=0;fault=async count=>{if(count===2)await pool.query("CREATE OR REPLACE FUNCTION license_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+interval '61 seconds'; $$");};
 await assert.rejects(transition(request,'activate'),error=>error.status===409);assert.equal((await pool.query('SELECT status FROM license_scope_activation_requests WHERE id=$1',[request.id])).rows[0].status,'approved');
 assert.equal((await pool.query('SELECT count(*)::int AS count FROM license_scope_grants')).rows[0].count,0);
});
test('eligibility expiry caps the actual activated lease and cannot be lifted by a later activation',async()=>{
 const license=await product();const eligibility=await eligible(license);
 await pool.query("CREATE OR REPLACE FUNCTION license_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+interval '3590 seconds'; $$");const request=await approved(eligibility);const active=await transition(request,'activate');assert.equal(active.grantExpiresAt,eligibility.expiresAt);
 await pool.query("CREATE OR REPLACE FUNCTION license_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+interval '3601 seconds'; $$");await assert.rejects(assign(license),error=>error.status===404);
});
test('a failing activation audit cannot leave an active lease or consume the approved request',async()=>{
 const license=await product();const request=await approved(await eligible(license));await pool.query("CREATE FUNCTION reject_activation_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='activate' THEN RAISE EXCEPTION 'Owned audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_activation_audit BEFORE INSERT ON license_scope_pim_audit FOR EACH ROW EXECUTE FUNCTION reject_activation_audit()");
 try{await assert.rejects(transition(request,'activate'),/Owned audit failure/);assert.equal((await pool.query('SELECT count(*)::int AS count FROM license_scope_grants')).rows[0].count,0);assert.equal((await pool.query('SELECT status FROM license_scope_activation_requests WHERE id=$1',[request.id])).rows[0].status,'approved');}
 finally{await pool.query('DROP TRIGGER reject_activation_audit ON license_scope_pim_audit; DROP FUNCTION reject_activation_audit()');}
});
test('a missed reviewer disable/reactivate or role regrant cannot restore an already approved activation',async()=>{
 const license=await product();const request=await approved(await eligible(license));people.get(reviewer.principal.userId).revision='3';await assert.rejects(transition(request,'activate'),error=>error.status===409);
 people.get(reviewer.principal.userId).revision='1';people.get(reviewer.principal.userId).fingerprint='e'.repeat(64);await assert.rejects(transition(request,'activate'),error=>error.status===409);
 assert.equal((await pool.query('SELECT count(*)::int AS count FROM license_scope_grants')).rows[0].count,0);
});
test('denial and own pending cancellation close only that request and never create an active grant',async()=>{
 const license=await product();const eligibility=await eligible(license);await assert.rejects(pim.request(eligibility.id,eligibilityTag(eligibility),{durationSeconds:301,...confirmation},delegate.user,delegate.principal,delegate.authorization),error=>error.status===400);
 const denied=await transition(await requested(eligibility),'decide',reviewer,{decision:'denied',...confirmation});assert.equal(denied.status,'denied');assert.equal(denied.canActivate,false);
 await assert.rejects(transition(denied,'activate'),error=>error.status===409);const cancelled=await transition(await requested(eligibility),'cancel');assert.equal(cancelled.status,'cancelled');
 await requested(eligibility);assert.equal((await pool.query('SELECT count(*)::int AS count FROM license_scope_grants')).rows[0].count,0);
});
test('reviewer loss during activation DML cannot issue a lease based on the earlier approval snapshot',async()=>{
 const license=await product();const request=await approved(await eligible(license));const original=source.delegate;let snapshots=0;
 source.delegate=async(...args)=>{snapshots++;if(snapshots===2)people.get(reviewer.principal.userId).enabled=false;return original(...args);};
 try{await assert.rejects(transition(request,'activate'),error=>error.status===409);assert.equal((await pool.query('SELECT status FROM license_scope_activation_requests WHERE id=$1',[request.id])).rows[0].status,'approved');}
 finally{source.delegate=original;}
});

async function policy(license,duty='allocator',who=policyAdmin){return policies.get(license.id,duty,who.user,who.principal);}
async function setPolicy(license,prepared,extra={},who=policyAdmin){const current=await policy(license,extra.duty||'allocator',who);const{duty='allocator',...fields}=extra;return policies.set(license.id,duty,policyTag(current),{activationRequired:true,maxDurationSeconds:300,preparedEligibilityIds:prepared.map(row=>row.id),acknowledgeInvalidation:true,...confirmation,...fields},who.user,who.principal,who.authorization);}
test('mandatory pool activation needs a separate MFA-bound policy duty and a live independent prepared path',async()=>{
 const license=await product();const eligibility=await eligible(license);assert.equal((await policy(license)).version,'1');await assert.rejects(setPolicy(license,[]),error=>error.status===400);
 await assert.rejects(setPolicy(license,[eligibility],{},owner),error=>error.status===403);const root=actor('admin');await assert.rejects(setPolicy(license,[eligibility],{},root),error=>error.status===403);
 await assert.rejects(setPolicy(license,[eligibility],{maxDurationSeconds:60}),error=>error.status===409);
 people.get(reviewer.principal.userId).enabled=false;await assert.rejects(setPolicy(license,[eligibility]),error=>error.status===409);people.get(reviewer.principal.userId).enabled=true;
 const configured=await setPolicy(license,[eligibility]);assert.equal(configured.version,'2');assert.equal(configured.activationRequired,true);assert.deepEqual(getLicensePermissions(policyAdmin.user),['licenses.scopepolicies.read','licenses.scopepolicies.manage']);
});
test('prepared adoption never blesses an old standing grant or pre-policy approval',async()=>{
 const license=await product();const eligibility=await eligible(license);const approval=await approved(eligibility);const standing=await grant(license);
 await setPolicy(license,[eligibility]);await assert.rejects(assign(license),error=>error.status===404);await assert.rejects(transition(approval,'activate'),error=>error.status===409);
 await assert.rejects(grant(license),error=>error.code==='42501');await store.revoke(standing.id,tag(standing),confirmation,owner.user,owner.principal,owner.authorization);await transition(approval,'cancel');
 const fresh=await transition(await approved(eligibility),'activate');await assign(license);assert.equal((await pool.query('SELECT policy_version FROM license_scope_grants WHERE id=$1',[fresh.grantId])).rows[0].policy_version,'2');
 const relaxed=await setPolicy(license,[],{activationRequired:false});assert.equal(relaxed.version,'3');await assert.rejects(assign(license),error=>error.status===404);
 await transition(fresh,'deactivate');const newStanding=await grant(license);assert.notEqual(newStanding.id,standing.id);await assign(license,delegate,actor('user'));
});
test('mandatory allocator policy protects global mutations and raw SQL without blocking the genuine PIM scope',async()=>{
 const license=await product();await allocator.assign(license.id,{assignee_type:'user',assignee_id:beneficiary.principal.userId},manager.principal.userId,manager);const eligibility=await eligible(license);await setPolicy(license,[eligibility]);
 await assert.rejects(allocator.assign(license.id,{assignee_type:'user',assignee_id:beneficiary.principal.userId},manager.principal.userId,manager),error=>error.status===403);
 await assert.rejects(allocator.revoke(license.id,beneficiary.principal.userId,manager.principal.userId,'user'),error=>error.status===403);
 await assert.rejects(pool.query('DELETE FROM license_assignment_sources WHERE license_id=$1',[license.id]),error=>error.code==='42501');await assert.rejects(pool.query('DELETE FROM license_assignments WHERE license_id=$1',[license.id]),error=>error.code==='42501');
 await assert.rejects(pool.query("INSERT INTO license_assignment_sources(license_id,user_id,source_type,source_id) VALUES($1,$2,'direct',$2)",[license.id,manager.principal.userId]),error=>error.code==='42501');
 await transition(await approved(eligibility),'activate');const target=actor('user');await assign(license,delegate,target);assert.equal((await pool.query('SELECT used_seats FROM license_catalog WHERE id=$1',[license.id])).rows[0].used_seats,2);
});
test('automatic approval cannot bypass allocator policy and only a real scoped approver can decide',async()=>{
 const license=await product();await pool.query('UPDATE license_catalog SET auto_approve=true WHERE id=$1',[license.id]);const allocationPath=await eligible(license);await setPolicy(license,[allocationPath]);
 const request=(await allocator.request(license.id,{requester_id:beneficiary.principal.userId,assignee_type:'user',assignee_id:beneficiary.principal.userId},beneficiary)).record;assert.equal(request.status,'pending');
 await assert.rejects(allocator.review(request.id,manager.principal.userId,'approved',manager),error=>error.status===403);
 const approvalPath=await eligible(license,{duty:'approver'});await transition(await approved(approvalPath),'activate');await run(license,'requests.review',()=>allocator.review(request.id,delegate.principal.userId,'approved',delegate));
 assert.equal((await pool.query('SELECT used_seats FROM license_catalog WHERE id=$1',[license.id])).rows[0].used_seats,1);
});
test('group auto approval and manual reconciliation cannot bypass policy but canonical background derivation survives',async()=>{
 const license=await product();const groupId=randomUUID();teams.set(groupId,{revision:'1',members:[beneficiary.principal.userId]});await allocator.assign(license.id,{assignee_type:'group',assignee_id:groupId},manager.principal.userId,manager);
 const eligibility=await eligible(license);await setPolicy(license,[eligibility]);const added=actor('user');teams.get(groupId).members.push(added.principal.userId);teams.get(groupId).revision='2';
 await assert.rejects(groups.reconcile(license.id,groupId,manager.principal.userId,manager),error=>error.status===403);const reconciled=await groups.reconcileAll(manager.authorization);assert.equal(reconciled[0]?.error,undefined,JSON.stringify(reconciled));
 assert.equal((await pool.query('SELECT used_seats FROM license_catalog WHERE id=$1',[license.id])).rows[0].used_seats,2);
 await assert.rejects(allocator.revoke(license.id,groupId,manager.principal.userId,'group'),error=>error.status===403);
 const another=randomUUID();teams.set(another,{revision:'1',members:[beneficiary.principal.userId]});await pool.query('UPDATE license_catalog SET auto_approve=true WHERE id=$1',[license.id]);
 const result=await allocator.request(license.id,{requester_id:beneficiary.principal.userId,assignee_type:'group',assignee_id:another},beneficiary);assert.equal(result.record.status,'pending');
});
test('security offboarding, canonical disablement and expiry cleanup remain possible without live administrators',async()=>{
 const license=await product();await allocator.assign(license.id,{assignee_type:'user',assignee_id:beneficiary.principal.userId},manager.principal.userId,manager);await setPolicy(license,[await eligible(license)]);
 await allocator.offboard(beneficiary.principal.userId,manager.principal.userId);assert.equal((await pool.query('SELECT used_seats FROM license_catalog WHERE id=$1',[license.id])).rows[0].used_seats,0);
});
test('policy versions are conditional and irreversible even when activation is later relaxed',async()=>{
 const license=await product();const original=await policy(license);const eligibility=await eligible(license);await setPolicy(license,[eligibility]);
 await assert.rejects(policies.set(license.id,'allocator',policyTag(original),{activationRequired:false,maxDurationSeconds:300,preparedEligibilityIds:[],acknowledgeInvalidation:true,...confirmation},policyAdmin.user,policyAdmin.principal,policyAdmin.authorization),error=>error.status===412);
 await assert.rejects(pool.query('DELETE FROM license_scope_activation_policies'),error=>error.code==='42501');await assert.rejects(pool.query('UPDATE license_scope_policy_audit SET reason=\'forged policy reason\''),error=>error.code==='42501');
 await assert.rejects(pool.query('UPDATE license_scope_eligibilities SET policy_version=2'),error=>error.code==='42501');
});
test('policy writer cannot prepare its own eligibility or a path whose reviewer is the writer',async()=>{
 const license=await product();const eligibility=await eligible(license);delegate.user.roles.push('license-scope-policy-administrator');await assert.rejects(setPolicy(license,[eligibility],{},delegate),error=>error.status===409);
 reviewer.user.roles.push('license-scope-policy-administrator');await assert.rejects(setPolicy(license,[eligibility],{},reviewer),error=>error.status===409);
 owner.user.roles.push('license-scope-policy-administrator');await assert.rejects(setPolicy(license,[eligibility],{},owner),error=>error.status===409);
});
test('issuer loss inside policy audit rolls back policy, evidence and all apparent authority invalidation',async()=>{
 const license=await product();const standing=await grant(license);const eligibility=await eligible(license);validations=0;fault=async count=>{if(count===2)throw Object.assign(new Error('Owned policy issuer withdrawal'),{status:401});};
 await assert.rejects(setPolicy(license,[eligibility]),error=>error.status===401);fault=null;assert.equal((await policy(license)).version,'1');await assign(license);
 assert.equal((await pool.query('SELECT license_scope_grant_usable($1) AS usable',[standing.id])).rows[0].usable,true);assert.equal((await pool.query('SELECT count(*)::int AS count FROM license_scope_policy_audit')).rows[0].count,0);
});
test('reader policy governs delegated reader incarnations without granting allocation or policy control',async()=>{
 const license=await product();const eligibility=await eligible(license,{duty:'reader'});const standing=await grant(license,'reader');await setPolicy(license,[eligibility],{duty:'reader'});
 await assert.rejects(run(license,'pool.read',()=>store.read(license.id,async()=>true,delegate.principal.userId)),error=>error.status===404);await store.revoke(standing.id,tag(standing),confirmation,owner.user,owner.principal,owner.authorization);
 await transition(await approved(eligibility),'activate');assert.equal(await run(license,'pool.read',()=>store.read(license.id,async()=>true,delegate.principal.userId)),true);await assert.rejects(assign(license),error=>error.status===404);
 const reader=actor('license-scope-policy-reader');assert.equal((await policy(license,'reader',reader)).activationRequired,true);await assert.rejects(setPolicy(license,[eligibility],{duty:'reader'},reader),error=>error.status===403);
});
test('a protected scope cannot reconfigure policy and the last peer check cannot accept a lost reviewer',async()=>{
 const license=await product();const eligibility=await eligible(license);await grant(license);delegate.user.roles.push('license-scope-policy-administrator');
 await assert.rejects(run(license,'assignments.manage',()=>setPolicy(license,[],{activationRequired:false},delegate)),error=>error.status===403);
 validations=0;fault=async count=>{if(count===2)people.get(reviewer.principal.userId).enabled=false;};await assert.rejects(setPolicy(license,[eligibility]),error=>error.status===409);
 assert.equal((await policy(license)).version,'1');assert.equal((await pool.query('SELECT count(*)::int AS count FROM license_scope_policy_audit')).rows[0].count,0);
});
test('raw source insertion waiting on a pool cannot bypass policy committed during that actual lock wait',async()=>{
 const license=await product();const eligibility=await eligible(license);const blocker=await pool.connect();let pending;
 try{await blocker.query('BEGIN');await blocker.query('SELECT id FROM license_catalog WHERE id=$1 FOR UPDATE',[license.id]);pending=pool.query("INSERT INTO license_assignment_sources(license_id,user_id,source_type,source_id) VALUES($1,$2,'direct',$2)",[license.id,beneficiary.principal.userId]);pending.catch(()=>{});
  let waiting=false;for(let attempt=0;attempt<200;attempt++){waiting=(await pool.query("SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'INSERT INTO license_assignment_sources(license_id,user_id,source_type,source_id)%'")).rows.length>0;if(waiting)break;await new Promise(resolve=>setTimeout(resolve,10));}assert.equal(waiting,true);
  await store.context(blocker,confirmation,policyAdmin.user,policyAdmin.principal);await blocker.query("SELECT set_config('opendirectory.scope_policy_action','set',true)");await blocker.query("INSERT INTO license_scope_activation_policies(license_id,duty,version,activation_required,max_duration_seconds,prepared_eligibility_ids,updated_by) VALUES($1,'allocator',2,true,300,$2,$3)",[license.id,[eligibility.id],policyAdmin.principal.userId]);await blocker.query('COMMIT');
  await assert.rejects(pending,error=>error.code==='42501');assert.equal((await pool.query('SELECT count(*)::int AS count FROM license_assignment_sources WHERE license_id=$1',[license.id])).rows[0].count,0);
 }finally{await blocker.query('ROLLBACK');blocker.release();if(pending)await pending.catch(()=>{});}
});
test('a failing policy audit and an expiring final prepared path cannot commit authority invalidation',async()=>{
 const license=await product();const eligibility=await eligible(license);await pool.query("CREATE FUNCTION reject_pool_policy_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Owned pool policy audit failure'; END $$; CREATE TRIGGER reject_pool_policy_audit BEFORE INSERT ON license_scope_policy_audit FOR EACH ROW EXECUTE FUNCTION reject_pool_policy_audit()");
 try{await assert.rejects(setPolicy(license,[eligibility]),/Owned pool policy audit failure/);}finally{await pool.query('DROP TRIGGER reject_pool_policy_audit ON license_scope_policy_audit;DROP FUNCTION reject_pool_policy_audit()');}
 validations=0;fault=async count=>{if(count===2)await pool.query("CREATE OR REPLACE FUNCTION license_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+interval '3301 seconds'; $$");};await assert.rejects(setPolicy(license,[eligibility]),error=>error.status===409);assert.equal((await policy(license)).version,'1');
 await pool.query('CREATE OR REPLACE FUNCTION license_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp(); $$');validations=0;fault=async count=>{if(count===3)await pool.query("CREATE OR REPLACE FUNCTION license_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+interval '3301 seconds'; $$");};await assert.rejects(setPolicy(license,[eligibility]),error=>error.status===409);assert.equal((await policy(license)).version,'1');
});
test('source expiry still releases real seats while mandatory PIM remains enabled',async()=>{
 const license=await product();await allocator.assign(license.id,{assignee_type:'user',assignee_id:beneficiary.principal.userId,expires_at:new Date(Date.now()+60000).toISOString()},manager.principal.userId,manager);await setPolicy(license,[await eligible(license)]);
 await pool.query("CREATE OR REPLACE FUNCTION license_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+interval '61 seconds'; $$");await allocator.expireAll();assert.equal((await pool.query('SELECT used_seats FROM license_catalog WHERE id=$1',[license.id])).rows[0].used_seats,0);assert.equal((await policy(license)).activationRequired,true);
});
test('independent source-review withdrawal still removes actual direct and group rights under mandatory PIM',async()=>{
 const license=await product();await allocator.assign(license.id,{assignee_type:'user',assignee_id:beneficiary.principal.userId},manager.principal.userId,manager);const groupId=randomUUID();teams.set(groupId,{revision:'1',members:[beneficiary.principal.userId]});await allocator.assign(license.id,{assignee_type:'group',assignee_id:groupId},manager.principal.userId,manager);
 const configurer=actor('license-review-administrator');const voter=actor('license-reviewer');const reviews=new LicenseReviews(allocator,{source:{...source,reviewer:async userId=>({canReview:people.get(userId)?.role==='license-reviewer'&&people.get(userId)?.enabled===true})},revalidate:async()=>{}});
 await reviews.create({licenseId:license.id,intervalSeconds:3600,windowSeconds:60,reviewerUserIds:[voter.principal.userId],reason:'Independently review actual recipient sources',acknowledgeDeadlines:true},configurer.user,configurer.principal,configurer.authorization);await setPolicy(license,[await eligible(license)]);
 const rows=(await reviews.self(voter.user,voter.principal)).reviews;assert.equal(rows.length,2);for(const row of rows)await reviews.decide(row.id,licenseReviewTag(row),{decision:'deny',reason:'Independent source withdrawal is not ordinary allocation',acknowledgeScope:true},voter.user,voter.principal,voter.authorization);
 assert.equal((await pool.query('SELECT used_seats FROM license_catalog WHERE id=$1',[license.id])).rows[0].used_seats,0);assert.equal((await policy(license)).activationRequired,true);
});

async function longGrant(license){return store.create({licenseId:license.id,userId:delegate.principal.userId,duty:'allocator',durationSeconds:3600,...confirmation},owner.user,owner.principal,owner.authorization);}
async function reviewPolicy(license,kind='grant',extra={}){return scopeReviews.create({licenseId:license.id,duty:'allocator',targetKind:kind,intervalSeconds:300,windowSeconds:60,reviewerUserIds:[scopeVoter.principal.userId],acknowledgeCutoffs:true,...confirmation,...extra},reviewAdmin.user,reviewAdmin.principal,reviewAdmin.authorization);}
async function reviewRows(who=scopeVoter){return(await scopeReviews.list(false,who.user,who.principal)).reviews;}
async function scopeVote(row,decision='retain',who=scopeVoter){return scopeReviews.decide(row.id,scopeReviewTag(row),{decision,acknowledgeScope:true,...confirmation},who.user,who.principal,who.authorization);}
async function advance(seconds){await pool.query(`CREATE OR REPLACE FUNCTION license_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+interval '${seconds} seconds'; $$`);}
test('administrative grant reviews capture current/future UUIDs and remove actual authority at unanswered deadlines',async()=>{
 const license=await product();await longGrant(license);await reviewPolicy(license);const rows=await reviewRows();assert.equal(rows.length,1);assert.equal(rows[0].canRetain,true);await assign(license);await advance(61);
 await assert.rejects(assign(license),error=>error.status===404);assert.equal((await pool.query('SELECT used_seats FROM license_catalog WHERE id=$1',[license.id])).rows[0].used_seats,1);assert.equal((await scopeReviews.get(rows[0].id,scopeVoter.user,scopeVoter.principal)).state,'expired');
});
test('timely independent retention advances only the review cycle and never changes the grant base expiry',async()=>{
 const license=await product();const grant=await longGrant(license);await reviewPolicy(license);const original=(await reviewRows())[0];const retained=await scopeVote(original);assert.equal(retained.cycle,'2');assert.equal(retained.state,'scheduled');assert.equal(retained.baseExpiresAt,grant.expiresAt);await advance(61);await assign(license);
 await assert.rejects(scopeVote(original),error=>error.status===412);await advance(361);await assert.rejects(assign(license),error=>error.status===404);
});
test('denying a grant review conditionally revokes only administrative authority, not business licenses',async()=>{
 const license=await product();const grant=await longGrant(license);await assign(license);await reviewPolicy(license);const denied=await scopeVote((await reviewRows())[0],'deny');assert.equal(denied.state,'denied');assert.equal(denied.targetVersion,'2');await assert.rejects(assign(license),error=>error.status===404);
 assert.ok((await pool.query('SELECT revoked_at FROM license_scope_grants WHERE id=$1',[grant.id])).rows[0].revoked_at);assert.equal((await pool.query('SELECT used_seats FROM license_catalog WHERE id=$1',[license.id])).rows[0].used_seats,1);
});
test('a captured review has no self, original grantor or policy-configurator approval bypass',async()=>{
 const license=await product();await longGrant(license);delegate.user.roles.push('license-delegation-reviewer');people.get(delegate.principal.userId).scopeReview=true;await assert.rejects(reviewPolicy(license,'grant',{reviewerUserIds:[delegate.principal.userId]}),error=>error.status===409);
 owner.user.roles.push('license-delegation-reviewer');people.get(owner.principal.userId).scopeReview=true;await assert.rejects(reviewPolicy(license,'grant',{reviewerUserIds:[owner.principal.userId]}),error=>error.status===409);await reviewPolicy(license);const row=(await reviewRows())[0];await assert.rejects(scopeVote(row,'retain',delegate),error=>error.status===403);
 const root=actor('admin');await assert.rejects(scopeVote(row,'retain',root),error=>error.status===403);
});
test('review duties do not inherit allocation, eligibility configuration or policy editing from one another',async()=>{
 const license=await product();await longGrant(license);await assert.rejects(reviewPolicy(license,'grant',{reviewerUserIds:[reviewAdmin.principal.userId]}),error=>[400,409].includes(error.status));await reviewPolicy(license);const row=(await reviewRows())[0];await assert.rejects(scopeVote(row,'retain',reviewAdmin),error=>error.status===403);
 assert.deepEqual(getLicensePermissions(scopeVoter.user),['licenses.scopereviews.assigned.read','licenses.scopereviews.decide']);await assert.rejects(pim.create({licenseId:license.id},scopeVoter.user,scopeVoter.principal,scopeVoter.authorization),error=>error.status===403);
});
test('parallel review decisions cannot consume the same version or silently retry a changed target',async()=>{
 const license=await product();await longGrant(license);await reviewPolicy(license);const row=(await reviewRows())[0];const results=await Promise.allSettled([scopeVote(row),scopeVote(row,'deny')]);assert.equal(results.filter(result=>result.status==='fulfilled').length,1);assert.equal(results.find(result=>result.status==='rejected').reason.status,412);
});
test('eligibility review attachment and retention fence earlier pending approvals',async()=>{
 const license=await product();const eligibility=await eligible(license);const old=await approved(eligibility);await reviewPolicy(license,'eligibility');await assert.rejects(transition(old,'activate'),error=>error.status===409);await transition(old,'cancel');
 const pending=await transition(await requested(eligibility,300),'decide',reviewer,{decision:'approved',...confirmation});await scopeVote((await reviewRows())[0]);await assert.rejects(transition(pending,'activate'),error=>error.status===409);await transition(pending,'cancel');
 const current=await transition(await requested(eligibility,300),'decide',reviewer,{decision:'approved',...confirmation});assert.equal((await transition(current,'activate')).status,'activated');
});
test('parent eligibility review fences existing PIM grants without extending them after timely parent retention',async()=>{
 const license=await product();const eligibility=await eligible(license);const approvedRequest=await transition(await requested(eligibility,300),'decide',reviewer,{decision:'approved',...confirmation});const active=await transition(approvedRequest,'activate');await reviewPolicy(license,'eligibility');const row=(await reviewRows())[0];await scopeVote(row);await advance(61);
 assert.equal((await pool.query('SELECT license_scope_eligibility_usable($1,1) AS usable',[eligibility.id])).rows[0].usable,true);assert.equal((await pool.query('SELECT expires_at>license_now() AS live FROM license_scope_grants WHERE id=$1',[active.grantId])).rows[0].live,true);await assert.rejects(assign(license),error=>error.status===404);
});
test('new activations are physically capped to the reviewed eligibility deadline',async()=>{
 const license=await product();const eligibility=await eligible(license);await reviewPolicy(license,'eligibility');const row=(await reviewRows())[0];const approvedRequest=await transition(await requested(eligibility,300),'decide',reviewer,{decision:'approved',...confirmation});const active=await transition(approvedRequest,'activate');assert.equal(active.grantExpiresAt,row.deadlineAt);await advance(61);await assert.rejects(assign(license),error=>error.status===404);
});
test('eligibility denial revokes its durable parent and removes actual child PIM authority',async()=>{
 const license=await product();const eligibility=await eligible(license);const active=await transition(await approved(eligibility),'activate');await assign(license);await reviewPolicy(license,'eligibility');const denied=await scopeVote((await reviewRows())[0],'deny');assert.equal(denied.targetVersion,'2');await assert.rejects(assign(license),error=>error.status===404);
 await transition(active,'deactivate');assert.equal((await pool.query('SELECT used_seats FROM license_catalog WHERE id=$1',[license.id])).rows[0].used_seats,1);
});
test('retirement and replacement cannot erase the accepted administrative cutoff or resurrect its UUID',async()=>{
 const license=await product();await longGrant(license);const policy=await reviewPolicy(license);const row=(await reviewRows())[0];await scopeReviews.retire(policy.id,scopeReviewPolicyTag(policy),confirmation,reviewAdmin.user,reviewAdmin.principal,reviewAdmin.authorization);await reviewPolicy(license);assert.equal((await pool.query('SELECT count(*)::int AS count FROM license_scope_review_leases')).rows[0].count,1);await advance(61);await assert.rejects(assign(license),error=>error.status===404);await assert.rejects(scopeVote(row),error=>error.status===412);
});
test('expired eligibility review cannot be adopted as a mandatory-policy prepared activation path',async()=>{
 const license=await product();const eligibility=await eligible(license);await reviewPolicy(license,'eligibility');await assert.rejects(setPolicy(license,[eligibility]),error=>error.status===409);await scopeVote((await reviewRows())[0]);await setPolicy(license,[eligibility]);await advance(361);await assert.rejects(setPolicy(license,[eligibility]),error=>error.status===409);
});
test('a scoped callback cannot control its review or fabricate review evidence',async()=>{
 const license=await product();await longGrant(license);await reviewPolicy(license);delegate.user.roles.push('license-delegation-reviewer');await assert.rejects(run(license,'assignments.manage',()=>scopeVote(({}),'retain',delegate)),error=>error.status===403);
 await assert.rejects(pool.query('DELETE FROM license_scope_review_leases'),error=>error.code==='42501');await assert.rejects(pool.query('UPDATE license_scope_review_audit SET reason=\'forged scope audit\''),error=>error.code==='42501');await assert.rejects(pool.query("INSERT INTO license_scope_review_fences(grant_id,review_id,ceiling) SELECT target_id,id,license_now() FROM license_scope_review_leases LIMIT 1"),error=>error.code==='42501');
});
test('post-DML issuer withdrawal rolls back retention and audit rather than extending a stale administrative lease',async()=>{
 const license=await product();await longGrant(license);await reviewPolicy(license);const row=(await reviewRows())[0];validations=0;fault=async count=>{if(count===2)throw Object.assign(new Error('Owned scope review issuer withdrawal'),{status:401});};await assert.rejects(scopeVote(row),error=>error.status===401);fault=null;const current=await scopeReviews.get(row.id,scopeVoter.user,scopeVoter.principal);assert.equal(current.version,'1');assert.equal(current.deadlineAt,row.deadlineAt);
});
test('retention finishing after the captured response deadline rolls back its apparent next cycle',async()=>{
 await pool.query('CREATE TABLE owned_review_clock(offset_seconds integer NOT NULL)');await pool.query('INSERT INTO owned_review_clock VALUES(0)');await pool.query("CREATE OR REPLACE FUNCTION license_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+offset_seconds*interval '1 second' FROM owned_review_clock; $$");
 const license=await product();await longGrant(license);await reviewPolicy(license);const row=(await reviewRows())[0];validations=0;fault=async count=>{if(count===3)await pool.query('UPDATE owned_review_clock SET offset_seconds=61');};await assert.rejects(scopeVote(row),error=>error.status===409);assert.equal((await pool.query('SELECT version FROM license_scope_review_leases WHERE id=$1',[row.id])).rows[0].version,'1');
});
test('failed and successful service migration replay preserve captured review identity, retained cycle and actual unanswered cutoff',async()=>{
 const license=await product();await longGrant(license);await reviewPolicy(license);await scopeVote((await reviewRows())[0]);const original=(await pool.query('SELECT * FROM license_scope_review_leases')).rows[0];
 const previousUrl=process.env.DATABASE_URL;const url=new URL(process.env.LICENSE_TEST_DATABASE_URL);url.searchParams.set('options',`-c search_path=${schema},public`);process.env.DATABASE_URL=url.toString();const database=require('../../db/postgres');
 try{
  await advance(901);const ownedPool=database.getPool();const connect=ownedPool.connect.bind(ownedPool);let failReplay=true;
  ownedPool.connect=async()=>{const client=await connect();const query=client.query.bind(client);client.query=async(...args)=>{const result=await query(...args);if(failReplay&&args[0].includes('CREATE TABLE IF NOT EXISTS license_scope_activation_policies')){failReplay=false;throw Object.assign(new Error('Owned replay interruption after older authority helpers'),{code:'42501'});}return result;};return client;};
  await assert.rejects(database.runMigrations(),error=>error.code==='42501');ownedPool.connect=connect;
  assert.equal((await pool.query('SELECT license_scope_grant_usable(target_id) AS usable FROM license_scope_review_leases')).rows[0].usable,false);assert.deepEqual((await pool.query('SELECT * FROM license_scope_review_leases')).rows[0],original);
  await advance(0);await database.runMigrations();
 }finally{await database.shutdown();if(previousUrl===undefined)delete process.env.DATABASE_URL;else process.env.DATABASE_URL=previousUrl;}
 assert.deepEqual((await pool.query('SELECT * FROM license_scope_review_leases')).rows[0],original);await assign(license);await advance(901);await assert.rejects(assign(license),error=>error.status===404);
});
test('a rule captures future grants and rejects a future self-only grant before any authority or evidence can commit',async()=>{
 const license=await product();await reviewPolicy(license);const grant=await longGrant(license);assert.equal((await reviewRows())[0].targetId,grant.id);
 const other=await product();people.get(delegate.principal.userId).scopeReview=true;await reviewPolicy(other,'grant',{reviewerUserIds:[delegate.principal.userId]});await assert.rejects(longGrant(other),error=>error.code==='23514');assert.equal((await pool.query('SELECT count(*)::int AS count FROM license_scope_grants WHERE license_id=$1',[other.id])).rows[0].count,0);
});
test('an original PIM activation reviewer cannot recertify its own issued administrative grant',async()=>{
 const license=await product();await transition(await approved(await eligible(license)),'activate');reviewer.user.roles.push('license-delegation-reviewer');people.get(reviewer.principal.userId).scopeReview=true;
 await assert.rejects(reviewPolicy(license,'grant',{reviewerUserIds:[reviewer.principal.userId]}),error=>error.status===409);await reviewPolicy(license,'grant',{reviewerUserIds:[reviewer.principal.userId,scopeVoter.principal.userId]});const row=(await reviewRows(reviewer))[0];assert.equal(row.selfReview,true);assert.equal(row.canDeny,false);await assert.rejects(scopeVote(row,'retain',reviewer),error=>error.status===403);
});
test('target incarnation replacement during the final issuer check rolls back apparent retention',async()=>{
 const license=await product();await longGrant(license);await reviewPolicy(license);const row=(await reviewRows())[0];validations=0;fault=async count=>{if(count===2)people.get(delegate.principal.userId).fingerprint='b'.repeat(64);};await assert.rejects(scopeVote(row),error=>error.status===409);assert.equal((await pool.query('SELECT version FROM license_scope_review_leases WHERE id=$1',[row.id])).rows[0].version,'1');
});
