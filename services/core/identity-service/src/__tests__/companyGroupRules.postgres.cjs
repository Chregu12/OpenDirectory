'use strict';
const { test, beforeEach, afterEach, after } = require('node:test'); const assert = require('node:assert/strict'); const { randomUUID } = require('node:crypto');
const fs = require('node:fs'); const path = require('node:path'); const { Pool } = require('pg');
const { activeCompany } = require('../../../../../scripts/lib/company-owner-fixture.cjs'); const { adoptTenant } = require('../../../../../scripts/lib/tenant-ownership-fixture.cjs');
const { CompanyGroupRules } = require('../CompanyGroupRules'); const { CompanyLicenseAuthority } = require('../CompanyLicenseAuthority'); const { AuthorizationState } = require('../AuthorizationState');
const { DirectoryCreator } = require('../DirectoryCreator'); const { GroupMutator, groupEtag } = require('../GroupMutator'); const contract = require('../../../../../packages/company-group-rule-contract');
const issuer = 'https://group-rules.native'; const bearer = 'Bearer actual-company-owner'; const administration = new Pool({ connectionString: process.env.IDENTITY_TEST_DATABASE_URL, max: 1 });
let schema, pool, database, owner, rules, creator, groups, beforeCommit;
beforeEach(async () => {
 schema = 'group_rules_' + randomUUID().replaceAll('-', ''); await administration.query('CREATE SCHEMA ' + schema);
 pool = new Pool({ connectionString: process.env.IDENTITY_TEST_DATABASE_URL, max: 8, options: `-c search_path=${schema},public -c timezone=UTC` }); beforeCommit = null;
 database = { isAvailable: () => true, query: (...args) => pool.query(...args), getClient: () => pool.connect(), transaction: async (operation, options = {}) => {
  const client = await pool.connect(); try { await client.query(options.readOnly ? 'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY' : 'BEGIN'); if (options.actor) await client.query("SELECT set_config('opendirectory.actor',$1,true)", [options.actor]); const result = await operation(client); if (!options.readOnly && beforeCommit) await beforeCommit(client); await client.query('COMMIT'); return result; } catch (error) { await client.query('ROLLBACK'); throw error; } finally { client.release(); }
 } };
 for (const file of fs.readdirSync(path.join(__dirname, '../../migrations')).filter(file => file.endsWith('.sql')).sort()) {
  try { await pool.query(fs.readFileSync(path.join(__dirname, '../../migrations', file), 'utf8')); } catch (error) { throw new Error(file + ': ' + error.message + ' ' + (error.where || '') + ' position ' + (error.position || '')); }
 }
 owner = await activeCompany(database, schema, issuer);
 const revalidate = async (_bearer, user) => (await new AuthorizationState(database).state(issuer, user.sub)).tenant;
 rules = new CompanyGroupRules(database, { authority: new CompanyLicenseAuthority(database, { issuer, revalidate }) });
 creator = new DirectoryCreator(database, { issuer, revalidate }); groups = new GroupMutator(database, { issuer, revalidate, revalidateAccess: async () => {} });
});
afterEach(async () => { beforeCommit = null; await pool.end(); await administration.query('DROP SCHEMA ' + schema + ' CASCADE'); }); after(async () => administration.end());
const group = name => creator.group({ name }, owner.user, bearer);
const input = (changes = {}) => ({ enabled: true, draft: { dynamic: { all: [{ attribute: 'department', operator: 'equals', value: 'Engineering' }] }, childGroupIds: [], excludedUserIds: [] }, reason: 'Explicit own-company dynamic and nested group configuration', confirm: true, ...changes });
const save = (collection, values = input(), revision = null, id = randomUUID()) => rules.save(collection.id, values, contract.etag(collection.id, revision), id, owner.user, bearer);
async function appWorker(grantOwner=owner) {
 const {CompanyAutomation}=require('../CompanyAutomation');const appBearer='Bearer actual-group-app';
 const app={iss:issuer,sub:'group-rule-app',client_id:'group-rule-app',client_revision:'1',actor_type:'application',token_use:'access',jti:randomUUID(),exp:Math.floor(Date.now()/1000)+3600,scope:'company.automation',permissions:['company.automation']};
 const automation=new CompanyAutomation(database,{issuer,authority:rules.authority,revalidate:async authorization=>assert.equal(authorization,appBearer)});
 const enrollment=await automation.enroll({id:randomUUID(),name:'Actual own group-rule worker'},app,appBearer);
 const permission=(await automation.approve({id:randomUUID(),enrollmentId:enrollment.id,clientId:app.client_id,clientRevision:'1',actions:['directory.groups.reconcile'],expiresAt:new Date(Date.now()+3600000).toISOString(),reason:'Explicitly delegate actual own saved group-rule reconciliation',confirm:true},grantOwner.user,bearer)).grant;
 return {automation,app,appBearer,permission,queue:groupId=>automation.enqueue({id:randomUUID(),grantId:permission.id,action:'directory.groups.reconcile',format:'json',ruleId:groupId},app,appBearer),run:()=>automation.run({grantId:permission.id},app,appBearer)};
}
async function person(department, title = '') {
 const id = randomUUID(); await pool.query('INSERT INTO users(id,username,email,department,title) VALUES($1,$2,$3,$4,$5)', [id, 'employee-' + id, id + '@test.invalid', department, title]);
 await adoptTenant(database, schema, owner.receipt.tenantId, [{ kind: 'user', resourceId: id }]); return id;
}
test('an explicitly delegated real app creates canonical rule memberships after the owner session expires without inventing human authority',async()=>{
 const parent=await group('App-managed actual group');const userId=await person('Engineering');await save(parent);const worker=await appWorker();const queued=await worker.queue(parent.id);
 owner.user.auth_time-=301;owner.user.mfa_authorization.authTime-=301;
 const outcome=await worker.run();assert.equal(outcome.job.status,'succeeded',JSON.stringify(outcome));assert.equal(outcome.job.id,queued.job.id);
 const artifact=await worker.automation.result(queued.job.id,worker.app,worker.appBearer);const report=JSON.parse(artifact.content);
 assert.deepEqual(report.results,[{userId,status:'added',code:null}]);assert.equal(report.actor.kind,'application');assert.equal(report.actor.id,worker.permission.id);
 const origin=(await pool.query('SELECT * FROM identity_membership_origins WHERE group_id=$1 AND user_id=$2',[parent.id,userId])).rows[0];assert.equal(origin.created_by,null);assert.equal(origin.application_grant_id,worker.permission.id);
 const event=(await pool.query("SELECT actor FROM identity_directory_group_events WHERE group_id=$1 AND action='member-add'",[parent.id])).rows[0];
 assert.deepEqual(event.actor,{kind:'application',grantId:worker.permission.id,clientId:worker.app.client_id,clientRevision:'1'});
 const source=(await pool.query('SELECT source FROM identity_company_group_rule_effects WHERE group_id=$1',[parent.id])).rows[0].source;
 for(const key of ['context','actorUserId','mfa_authorization','auth_time','roles'])assert.equal(Object.hasOwn(source.authority,key),false);
 assert.equal((await pool.query('SELECT count(*)::integer AS count FROM identity_company_group_rule_steps')).rows[0].count,1);
});
test('the app removes only obsolete rule sources and cannot address another tenant or bypass a disabled receiving guard',async()=>{
 let parent=await group('App removal and source fence');const engineer=await person('Engineering');const manual=await person('Operations');parent=await groups.add(parent.id,{userId:manual},groupEtag(parent),owner.user,bearer);
 await save(parent);const worker=await appWorker();await worker.queue(parent.id);assert.equal((await worker.run()).job.status,'succeeded');
 await save(parent,input({enabled:false}),'1');await worker.queue(parent.id);const removed=await worker.run();assert.equal(removed.job.status,'succeeded',JSON.stringify(removed));
 const report=JSON.parse((await worker.automation.result(removed.job.id,worker.app,worker.appBearer)).content);assert.deepEqual(report.results,[{userId:engineer,status:'removed',code:null}]);
 assert.deepEqual((await pool.query('SELECT user_id FROM group_members WHERE group_id=$1',[parent.id])).rows.map(row=>row.user_id),[manual]);
 const foreignOwner=await activeCompany(database,schema,issuer);const foreign=await creator.group({name:'Foreign app target'},foreignOwner.user,bearer);await worker.queue(foreign.id);
 assert.equal((await worker.run()).job.status,'failed');assert.equal((await pool.query('SELECT count(*)::integer AS count FROM group_members WHERE group_id=$1',[foreign.id])).rows[0].count,0);
 await worker.queue(parent.id);await pool.query('ALTER TABLE group_members DISABLE TRIGGER identity_directory_group_commit');
 assert.equal((await worker.run()).job.status,'retry_wait');await pool.query('ALTER TABLE group_members ENABLE TRIGGER identity_directory_group_commit');
 await assert.rejects(pool.query('TRUNCATE identity_company_group_rule_runs CASCADE'),{code:'42501'});
});
test('missing durable step delivery evidence rolls back its membership and leaves the actual job unconfirmed',async()=>{
 const parent=await group('Suppressed app work receipt');await person('Engineering');await save(parent);const worker=await appWorker();await worker.queue(parent.id);
 await pool.query(`CREATE FUNCTION fixture_suppress_work_receipt() RETURNS TRIGGER LANGUAGE plpgsql AS $$BEGIN IF NEW.entity='step' THEN RETURN NULL;END IF;RETURN NEW;END;$$;
  CREATE TRIGGER aaa_fixture_suppress_work_receipt BEFORE INSERT ON identity_company_group_rule_work_outbox FOR EACH ROW EXECUTE FUNCTION fixture_suppress_work_receipt()`);
 const result=await worker.run();assert.equal(result.job.status,'retry_wait');assert.equal(result.job.artifactSha256,null);
 assert.equal((await pool.query('SELECT count(*)::integer AS count FROM group_members WHERE group_id=$1',[parent.id])).rows[0].count,0);
 assert.equal((await pool.query('SELECT count(*)::integer AS count FROM identity_company_group_rule_steps')).rows[0].count,0);
 assert.equal((await pool.query('SELECT count(*)::integer AS count FROM identity_company_group_rule_effects')).rows[0].count,0);
 await pool.query('DROP TRIGGER aaa_fixture_suppress_work_receipt ON identity_company_group_rule_work_outbox');
 await pool.query(`CREATE FUNCTION fixture_suppress_work_step() RETURNS TRIGGER LANGUAGE plpgsql AS $$BEGIN RETURN NULL;END;$$;
  CREATE TRIGGER aaa_fixture_suppress_work_step BEFORE INSERT ON identity_company_group_rule_steps FOR EACH ROW EXECUTE FUNCTION fixture_suppress_work_step()`);
 await worker.queue(parent.id);assert.equal((await worker.run()).job.status,'retry_wait');
 assert.equal((await pool.query('SELECT count(*)::integer AS count FROM group_members WHERE group_id=$1',[parent.id])).rows[0].count,0);
 assert.equal((await pool.query('SELECT count(*)::integer AS count FROM identity_company_group_rule_effects')).rows[0].count,0);
});
test('an imported mismatched app grant is not an effective membership source or an adoptable rule origin',async()=>{
 const parent=await group('Original machine provenance');const userId=await person('Engineering');await save(parent);const worker=await appWorker();await worker.queue(parent.id);assert.equal((await worker.run()).job.status,'succeeded');
 const membership=(await pool.query('SELECT membership_id FROM group_members WHERE group_id=$1 AND user_id=$2',[parent.id,userId])).rows[0].membership_id;
 assert.equal((await pool.query('SELECT identity_membership_application_origin($1) AS valid',[membership])).rows[0].valid,true);
 const foreignOwner=await activeCompany(database,schema,issuer);const foreign=await appWorker(foreignOwner);
 await pool.query('ALTER TABLE identity_membership_origins DISABLE TRIGGER identity_membership_evidence_guard');
 await pool.query('UPDATE identity_membership_origins SET application_grant_id=$1 WHERE membership_id=$2',[foreign.permission.id,membership]);
 await pool.query('ALTER TABLE identity_membership_origins ENABLE TRIGGER identity_membership_evidence_guard');
 assert.equal((await pool.query('SELECT identity_membership_review_allowed($1) AS allowed',[membership])).rows[0].allowed,false);
 await assert.rejects(rules.preview(parent.id,owner.user,bearer),{status:503});
});
test('the physical app token deadline rolls back a canonical step even after its last live check',async()=>{
 const parent=await group('Physical app expiry');await person('Engineering');await save(parent);const worker=await appWorker();await worker.queue(parent.id);
 worker.app.exp=Math.floor(Date.now()/1000)+3;let waited=false;
 beforeCommit=async client=>{const scope=(await client.query("SELECT NULLIF(current_setting('opendirectory.company_group_rule_work',true),'')::jsonb AS scope")).rows[0].scope;if(scope?.kind==='step'){waited=true;await client.query('SELECT pg_sleep(3.1)');}};
 await assert.rejects(worker.run());beforeCommit=null;assert.equal(waited,true);
 assert.equal((await pool.query('SELECT count(*)::integer AS count FROM group_members WHERE group_id=$1',[parent.id])).rows[0].count,0);
 assert.equal((await pool.query('SELECT count(*)::integer AS count FROM identity_company_group_rule_steps')).rows[0].count,0);
});
test('a changed rule reissues its exact old origins in a new captured cycle while preserving original run receipts',async()=>{
 const parent=await group('Actual rule version reissue');const userId=await person('Engineering');await save(parent);const worker=await appWorker();await worker.queue(parent.id);assert.equal((await worker.run()).job.status,'succeeded');
 const original=(await pool.query('SELECT membership_id FROM group_members WHERE group_id=$1 AND user_id=$2',[parent.id,userId])).rows[0].membership_id;
 const values=input();values.draft.dynamic.all[0].value='engineering';await save(parent,values,'1');const queued=await worker.queue(parent.id);
 const first=await worker.run();assert.equal(first.job.status,'queued',JSON.stringify(first));assert.equal(first.job.progress.cycle,2);assert.equal(first.job.progress.completed,0);
 const second=await worker.run();assert.equal(second.job.status,'succeeded',JSON.stringify(second));const actual=(await pool.query('SELECT membership_id FROM group_members WHERE group_id=$1 AND user_id=$2',[parent.id,userId])).rows[0].membership_id;assert.notEqual(actual,original);
 assert.deepEqual((await pool.query('SELECT cycle FROM identity_company_group_rule_runs WHERE job_id=$1 ORDER BY cycle',[queued.job.id])).rows.map(row=>row.cycle),[1,2]);
 await pool.query(fs.readFileSync(path.join(__dirname,'../../migrations/051_company_group_rule_automation.sql'),'utf8'));await pool.query(fs.readFileSync(path.join(__dirname,'../../migrations/052_live_company_group_rules.sql'),'utf8'));await pool.query(fs.readFileSync(path.join(__dirname,'../../migrations/053_company_automation_changes.sql'),'utf8'));await pool.query(fs.readFileSync(path.join(__dirname,'../../migrations/054_company_app_automation_tenants.sql'),'utf8'));await pool.query('SELECT identity_company_group_rule_live_receiving()');
 assert.equal((await pool.query('SELECT count(*)::integer AS count FROM identity_company_group_rule_steps WHERE run_id IN(SELECT id FROM identity_company_group_rule_runs WHERE job_id=$1)',[queued.job.id])).rows[0].count,2);
});
test('actual owner stores a conditional rule and preview evaluates real attributes, canonical child members and exclusions without pretending membership changes', async () => {
 const parent = await group('Parent'); let child = await group('Child'); const engineer = await person('Engineering', 'Developer'); const nested = await person('Operations'); const excluded = await person('Engineering');
 child = await groups.add(child.id, { userId: nested }, groupEtag(child), owner.user, bearer);
 const values = input(); values.draft.childGroupIds = [child.id]; values.draft.excludedUserIds = [excluded];
 const absent = await rules.get(parent.id, owner.user, bearer); assert.equal(absent.rule, null); assert.equal(absent.etag, contract.etag(parent.id, null));
 const saved = await save(parent, values); assert.equal(saved.rule.revision, '1'); assert.equal(saved.rule.tenantId, owner.receipt.tenantId); assert.equal(saved.outcome, 'applied');
 const preview = await rules.preview(parent.id, owner.user, bearer); assert.deepEqual(preview.desired.map(item => item.userId), [engineer, nested].sort()); assert.equal(preview.additions, 2); assert.equal(preview.executionMode, 'manual');
 assert.equal((await pool.query('SELECT count(*)::integer AS count FROM group_members WHERE group_id=$1', [parent.id])).rows[0].count, 0);
 assert.equal((await pool.query('SELECT count(*)::integer AS count FROM identity_company_group_rule_events')).rows[0].count, 1);
 await assert.rejects(pool.query('DELETE FROM identity_company_group_rule_events'), { code: '42501' });
});
test('own rule graph rejects self membership, canonical foreign children and new cycles before retaining configuration', async () => {
 const first = await group('First'); const second = await group('Second'); const third = await group('Third');
 const nested = childGroupIds => input({ draft: { dynamic: null, childGroupIds, excludedUserIds: [] } });
 await save(first, nested([second.id])); await save(second, nested([third.id]));
 await assert.rejects(save(third, nested([first.id])), { code: '23514' }); await assert.rejects(save(third, nested([third.id])), { status: 409 });
 const other = await activeCompany(database, schema, issuer); const foreign = await creator.group({ name: 'Foreign private child' }, other.user, bearer);
 await assert.rejects(save(third, nested([foreign.id])), { code: '23503' });
 await assert.rejects(rules.get(foreign.id, owner.user, bearer), { status: 404 });
 assert.equal((await pool.query('SELECT count(*)::integer AS count FROM identity_company_group_rules')).rows[0].count, 2);
});
test('configuration preserves original idempotent history, rejects stale versions and does not acknowledge a no-op', async () => {
 const parent = await group('Versioned'); const id = randomUUID(); const first = await save(parent, input(), null, id);
 assert.equal((await save(parent, input(), null, id)).outcome, 'already_applied');
 const changed = input({ enabled: false }); await assert.rejects(save(parent, changed), { status: 412 });
 const second = await save(parent, changed, first.rule.revision); assert.equal(second.rule.revision, '2');
 await assert.rejects(save(parent, changed, '2'), { status: 409 });
 const old = await save(parent, input(), null, id); assert.equal(old.outcome, 'already_applied'); assert.equal(old.rule.revision, '1');
 assert.equal((await rules.get(parent.id, owner.user, bearer)).rule.revision, '2');
 const original = (await pool.query('SELECT command FROM identity_company_group_rule_events WHERE id=$1', [id])).rows[0].command; assert.equal(JSON.stringify(original).includes(bearer), false);
});
test('dynamic comparisons are literal and case insensitive with AND semantics rather than user supplied SQL', async () => {
 const parent = await group('Literal'); const desired = await person('Engineering_%', 'Senior Developer'); await person('Engineering', 'Senior Developer'); await person('Engineering_%', 'Manager');
 const values = input(); values.draft.dynamic.all = [{ attribute: 'department', operator: 'equals', value: 'engineering_%' }, { attribute: 'title', operator: 'startsWith', value: 'senior' }, { attribute: 'title', operator: 'endsWith', value: 'Developer' }];
 await save(parent, values); assert.deepEqual((await rules.preview(parent.id, owner.user, bearer)).desired.map(item => item.userId), [desired]);
});
test('original deadline is checked at physical configuration commit and no event can be retained without its pending receipt', async () => {
 const parent = await group('Physical deadline'); owner.user.exp = Math.floor(Date.now() / 1000) + 2;
 beforeCommit = async () => { await new Promise(resolve => setTimeout(resolve, Math.max(1, owner.user.exp * 1000 - Date.now() + 50))); };
 await assert.rejects(save(parent), { code: '42501' }); beforeCommit = null;
 assert.equal((await pool.query('SELECT count(*)::integer AS count FROM identity_company_group_rules')).rows[0].count, 0);
});
test('configuration cannot piggyback an unrelated canonical mutation and disabled receivers reject instead of assuming success', async () => {
 const parent = await group('Scoped'); beforeCommit = client => client.query("UPDATE users SET title='Unrelated extra effect' WHERE id=$1", [owner.receipt.administratorId]);
 await assert.rejects(save(parent), { code: '42501' }); beforeCommit = null;
 assert.equal((await pool.query('SELECT count(*)::integer AS count FROM identity_company_group_rules')).rows[0].count, 0);
 await pool.query('ALTER TABLE identity_company_group_rules DISABLE TRIGGER company_group_rule_commit'); await assert.rejects(rules.get(parent.id, owner.user, bearer), { code: '42501' });
});
test('a canonical write before rule admission is rejected by its deferred original-source fence even if the scope is later cleared', async () => {
 const parent = await group('Earlier write'); const userId = await person('Unrelated profile'); const transaction = database.transaction; let changed = false;
 database.transaction = (operation,options={}) => transaction(async client => {
  if(!options.readOnly&&!changed){assert.equal((await client.query("UPDATE users SET title='Earlier unrelated effect' WHERE id=$1",[userId])).rowCount,1);changed=true;}
  const value=await operation(client);if(!options.readOnly)await client.query("SELECT set_config('opendirectory.company_group_rule','',true)");return value;
 },options);
 await assert.rejects(save(parent),{code:'42501'});database.transaction=transaction;assert.equal(changed,true);
 assert.equal((await pool.query('SELECT title FROM users WHERE id=$1',[userId])).rows[0].title,'');assert.equal((await pool.query('SELECT count(*)::integer AS count FROM identity_company_group_rules')).rows[0].count,0);
});
async function sync(collection) {
 const preview = await rules.preview(collection.id, owner.user, bearer); let cursor = null; const results = [];
 do { const page = await rules.sync(collection.id, { observation: preview.observation, cursor, reason: 'Explicit actual canonical group rule reconciliation', confirm: true }, owner.user, bearer); results.push(...page.results); cursor = page.nextCursor; } while (cursor);
 return results;
}
test('rule reconciliation creates actual memberships, preserves manual links and removes only its own original membership on disablement', async () => {
 let parent = await group('Actual materialized membership'); const managed = await person('Engineering'); const manualEngineer = await person('Engineering'); const manualOther = await person('Operations');
 parent = await groups.add(parent.id, { userId: manualEngineer }, groupEtag(parent), owner.user, bearer); parent = await groups.add(parent.id, { userId: manualOther }, groupEtag(parent), owner.user, bearer);
 await save(parent); const result = await sync(parent); assert.equal(result.find(item => item.userId === managed).status, 'added'); assert.equal(result.find(item => item.userId === manualEngineer).status, 'manual-retained');
 const first = (await pool.query('SELECT membership_id FROM group_members WHERE group_id=$1 AND user_id=$2', [parent.id, managed])).rows[0].membership_id;
 await save(parent, input({ enabled: false }), '1'); const removed = await sync(parent); assert.equal(removed.find(item => item.userId === managed).status, 'removed');
 assert.deepEqual((await pool.query('SELECT user_id FROM group_members WHERE group_id=$1 ORDER BY user_id', [parent.id])).rows.map(row => row.user_id), [manualEngineer, manualOther].sort());
 await save(parent, input(), '2'); await sync(parent);
 const next = (await pool.query('SELECT membership_id FROM group_members WHERE group_id=$1 AND user_id=$2', [parent.id, managed])).rows[0].membership_id; assert.notEqual(next, first);
 assert.equal((await pool.query('SELECT count(*)::integer AS count FROM identity_company_group_rule_effects')).rows[0].count, 3);
 const history = await rules.history(parent.id, {}, owner.user, bearer); assert.equal(history.total, 6); assert.equal(history.events.filter(item=>item.kind==='membership').length, 3);
 await assert.rejects(pool.query('DELETE FROM identity_company_group_rule_effects'), { code: '42501' });
 let current = (await pool.query('SELECT id,revision FROM groups WHERE id=$1',[parent.id])).rows[0];
 current = await groups.removeMember(parent.id,managed,groupEtag(current),owner.user,bearer);
 await groups.add(parent.id,{userId:managed},groupEtag(current),owner.user,bearer);
 const manualReplacement = (await pool.query('SELECT membership_id FROM group_members WHERE group_id=$1 AND user_id=$2',[parent.id,managed])).rows[0].membership_id;
 assert.notEqual(manualReplacement,next); await save(parent,input({enabled:false}),'3'); assert.deepEqual(await sync(parent),[]);
 assert.equal((await pool.query('SELECT membership_id FROM group_members WHERE group_id=$1 AND user_id=$2',[parent.id,managed])).rows[0].membership_id,manualReplacement);
 for(const file of ['050_company_group_rules.sql','051_company_group_rule_automation.sql','052_live_company_group_rules.sql','053_company_automation_changes.sql','054_company_app_automation_tenants.sql'])await pool.query(fs.readFileSync(path.join(__dirname,'../../migrations',file),'utf8'));
 assert.equal((await rules.get(parent.id,owner.user,bearer)).rule.revision,'4'); assert.equal((await rules.history(parent.id,{},owner.user,bearer)).total,7);
});
test('a silently suppressed pending effect receipt rolls back the actual canonical membership rather than acknowledging a partial write', async () => {
 const parent=await group('Missing actual effect receipt');const userId=await person('Engineering');await save(parent);
 await pool.query(`CREATE FUNCTION fixture_suppress_rule_receipt() RETURNS TRIGGER LANGUAGE plpgsql AS $$BEGIN RETURN NULL;END;$$;
  CREATE TRIGGER aaa_fixture_suppress_rule_receipt BEFORE INSERT ON identity_company_group_rule_effect_outbox FOR EACH ROW EXECUTE FUNCTION fixture_suppress_rule_receipt()`);
 await assert.rejects(sync(parent),{code:'42501'});
 assert.equal((await pool.query('SELECT count(*)::integer AS count FROM group_members WHERE group_id=$1',[parent.id])).rows[0].count,0);
 assert.equal((await pool.query('SELECT count(*)::integer AS count FROM identity_company_group_rule_effects')).rows[0].count,0);
 assert.equal((await pool.query("SELECT count(*)::integer AS count FROM identity_directory_group_events WHERE group_id=$1 AND action='member-add'",[parent.id])).rows[0].count,0);
 await pool.query('DROP TRIGGER aaa_fixture_suppress_rule_receipt ON identity_company_group_rule_effect_outbox');
 assert.equal((await sync(parent)).find(row=>row.userId===userId).status,'added');
});
test('a rule-generated canonical membership remains awaiting independent review and cannot propagate to a nested parent before approval', async () => {
 const { GroupMembershipReviews, reviewTag } = require('../GroupMembershipReviews'); const child = await group('Governed child'); const parent = await group('Waiting parent'); const userId = await person('Engineering');
 const authority = new AuthorizationState(database);
 const reviewer = async role => {
  const id = await person('Independent governance'); const subject = 'group-rule-reviewer-' + id;
  await pool.query('INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES($1,$2,$3)', [issuer,subject,id]);
  await pool.query('INSERT INTO identity_role_assignments(user_id,role,reason) VALUES($1,$2,$3)', [id,role,'Explicit independent fixture review duty']);
  const state = await authority.state(issuer,subject); const now = Math.floor(Date.now()/1000); return { actor_type:'user',iss:issuer,sub:subject,roles:state.roles,identity_authorization:state.context,jti:randomUUID(),exp:now+3600,auth_time:now,amr:['pwd','otp'],mfa_authorization:{schemaVersion:1,userId:id,revision:'1',authTime:now,methods:['pwd','otp']} };
 };
 const manager = await reviewer('group-review-administrator'); const voter = await reviewer('group-reviewer'); const reviews = new GroupMembershipReviews(database,{revalidate:async()=>{}});
 await reviews.create({groupId:child.id,intervalSeconds:300,windowSeconds:60,reviewerUserIds:[voter.identity_authorization.userId],reason:'Require actual independent initial membership approval',acknowledgeEffects:true},manager,bearer);
 await save(child); await save(parent,input({draft:{dynamic:null,childGroupIds:[child.id],excludedUserIds:[]}}));
 const results = await sync(child); assert.equal(results.find(item=>item.userId===userId).status,'awaiting-review');
 assert.equal((await rules.preview(parent.id,owner.user,bearer)).desired.length,0);
 const lease=(await pool.query('SELECT * FROM identity_membership_review_leases WHERE membership_id=(SELECT membership_id FROM group_members WHERE group_id=$1 AND user_id=$2)',[child.id,userId])).rows[0];
 assert.equal(lease.initial_grace,false);assert.equal(lease.projected_active,false);
 const before=await reviews.get(lease.id,voter);await reviews.decide(lease.id,reviewTag(before),{decision:'retain',reason:'Independent actual reviewed dynamic membership',acknowledgeScope:true},voter,bearer);
 assert.deepEqual((await rules.preview(parent.id,owner.user,bearer)).desired.map(item=>item.userId),[userId]);
 const appChild=await group('App-governed child');
 await reviews.create({groupId:appChild.id,intervalSeconds:300,windowSeconds:60,reviewerUserIds:[voter.identity_authorization.userId],reason:'Require actual independent approval for machine-created members',acknowledgeEffects:true},manager,bearer);
 await save(appChild);const worker=await appWorker();await worker.queue(appChild.id);owner.user.auth_time-=301;owner.user.mfa_authorization.authTime-=301;
 const first=await worker.run();assert.equal(first.job.status,'partial',JSON.stringify(first));const artifact=JSON.parse((await worker.automation.result(first.job.id,worker.app,worker.appBearer)).content);
 assert.deepEqual(artifact.results,[{userId,status:'awaiting-review',code:null}]);
 const appLease=(await pool.query('SELECT lease.id FROM identity_membership_review_leases lease JOIN identity_membership_origins origin ON origin.membership_id=lease.membership_id WHERE origin.group_id=$1 AND origin.user_id=$2',[appChild.id,userId])).rows[0];
 const pending=await reviews.get(appLease.id,voter);await reviews.decide(appLease.id,reviewTag(pending),{decision:'retain',reason:'Independent review of the actual machine-origin membership',acknowledgeScope:true},voter,bearer);
 await worker.automation.changeJob(first.job.id,'retry',`"company-automation-job-${first.job.id}-${first.job.revision}"`,worker.app,worker.appBearer);
 assert.equal((await worker.run()).job.status,'succeeded');
});
test('a new worker resumes the next actual page and keeps original receipts rather than repeating canonical adds',async()=>{
 const parent=await group('Paged machine group');for(let index=0;index<27;index++)await person('Engineering');await save(parent);const worker=await appWorker();const queued=await worker.queue(parent.id);
 const first=await worker.run();assert.equal(first.job.status,'queued',JSON.stringify(first));assert.equal(first.job.progress.completed,25);
 const {CompanyAutomation}=require('../CompanyAutomation');const restarted=new CompanyAutomation(database,{issuer,authority:rules.authority,revalidate:worker.automation.revalidate});
 const second=await restarted.run({grantId:worker.permission.id},worker.app,worker.appBearer);assert.equal(second.job.status,'succeeded',JSON.stringify(second));assert.equal(second.job.progress.completed,27);
 const report=JSON.parse((await restarted.result(queued.job.id,worker.app,worker.appBearer)).content);assert.equal(report.results.length,27);
 assert.equal((await pool.query("SELECT count(*)::integer AS count FROM identity_directory_group_events WHERE group_id=$1 AND action='member-add'",[parent.id])).rows[0].count,27);
 assert.equal((await pool.query('SELECT count(*)::integer AS count FROM identity_company_group_rule_steps')).rows[0].count,27);
});
test('nested rules use effective canonical child membership and remain ordinary actual memberships in each parent', async () => {
 const child = await group('Dynamic child'); const parent = await group('Nested parent'); const grandparent = await group('Nested grandparent'); const userId = await person('Engineering');
 await save(child); await save(parent, input({ draft: { dynamic: null, childGroupIds: [child.id], excludedUserIds: [] } })); await save(grandparent, input({ draft: { dynamic: null, childGroupIds: [parent.id], excludedUserIds: [] } }));
 assert.equal((await rules.preview(parent.id, owner.user, bearer)).desired.length, 0); await sync(child); await sync(parent); await sync(grandparent);
 for (const collection of [child, parent, grandparent]) assert.equal((await pool.query('SELECT count(*)::integer AS count FROM group_members WHERE group_id=$1 AND user_id=$2', [collection.id, userId])).rows[0].count, 1);
 await save(child, input({ enabled: false }), '1'); await sync(child); await sync(parent); await sync(grandparent);
 assert.equal((await pool.query('SELECT count(*)::integer AS count FROM group_members WHERE user_id=$1', [userId])).rows[0].count, 0);
});

async function snapshot(collection) {
 const {GroupSnapshotStore}=require('../GroupSnapshotStore');
 return new GroupSnapshotStore(database).snapshot(collection.id,null,{refreshReviews:false});
}
async function changeDepartment(userId,department) {
 const {UserMutator}=require('../UserMutator');const {userEtag,userFromRow}=require('../DirectoryUsers');
 const current=(await pool.query('SELECT * FROM users WHERE id=$1',[userId])).rows[0];
 const revalidate=async()=> (await new AuthorizationState(database).state(issuer,owner.user.sub)).tenant;
 return new UserMutator(database,{issuer,revalidate}).update(userId,{department},userEtag(userFromRow(current)),owner.user,bearer);
}
test('attribute loss immediately removes human and app rule sources from live authorization and snapshots across three levels before cleanup',async()=>{
 const child=await group('Live dynamic child');const parent=await group('Live nested parent');const root=await group('Live nested root');const userId=await person('Engineering');
 const subject='live-group-person-'+userId;await pool.query('INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES($1,$2,$3)',[issuer,subject,userId]);
 await save(child);await save(parent,input({draft:{dynamic:null,childGroupIds:[child.id],excludedUserIds:[]}}));await save(root,input({draft:{dynamic:null,childGroupIds:[parent.id],excludedUserIds:[]}}));
 const worker=await appWorker();await worker.queue(child.id);assert.equal((await worker.run()).job.status,'succeeded');await sync(parent);await sync(root);
 const first=await snapshot(root);assert.deepEqual(first.memberIds,[userId]);assert.equal((await new AuthorizationState(database).state(issuer,subject)).memberships.length,3);
 const physical=(await pool.query('SELECT id,revision FROM groups WHERE id=ANY($1::uuid[]) ORDER BY id',[[child.id,parent.id,root.id]])).rows;
 await changeDepartment(userId,'Operations');
 assert.deepEqual((await new AuthorizationState(database).state(issuer,subject)).memberships,[]);assert.equal((await new AuthorizationState(database).target('group',root.id,userId)).actorIsMember,true);
 for(const collection of [child,parent,root]){const current=await snapshot(collection);assert.deepEqual(current.memberIds,[]);assert.deepEqual(current.inactiveMemberIds,[userId]);const preview=await rules.preview(collection.id,owner.user,bearer);assert.equal(preview.existing[0].effective,false);assert.equal(preview.existing[0].validUntil,null);}
 const second=await snapshot(root);assert.ok(BigInt(second.revision)>BigInt(first.revision));
 assert.deepEqual((await pool.query('SELECT id,revision FROM groups WHERE id=ANY($1::uuid[]) ORDER BY id',[[child.id,parent.id,root.id]])).rows,physical);
 assert.equal((await pool.query('SELECT count(*)::integer AS count FROM group_members WHERE user_id=$1',[userId])).rows[0].count,3);
 await changeDepartment(userId,'Engineering');assert.deepEqual((await snapshot(root)).memberIds,[userId]);
});
test('removing the last real child link or changing a standing rule invalidates its materialized parent while retaining unrelated manual origins',async()=>{
 let child=await group('Live manual child');let parent=await group('Live source parent');const nested=await person('Operations');const manual=await person('Operations');
 child=await groups.add(child.id,{userId:nested},groupEtag(child),owner.user,bearer);parent=await groups.add(parent.id,{userId:manual},groupEtag(parent),owner.user,bearer);
 const draft={dynamic:null,childGroupIds:[child.id],excludedUserIds:[]};await save(parent,input({draft}));await sync(parent);const first=await snapshot(parent);
 await groups.removeMember(child.id,nested,groupEtag(child),owner.user,bearer);const second=await snapshot(parent);assert.deepEqual(second.memberIds,[manual]);assert.ok(BigInt(second.revision)>BigInt(first.revision));
 const current=(await pool.query('SELECT id,revision FROM groups WHERE id=$1',[child.id])).rows[0];await groups.add(child.id,{userId:nested},groupEtag(current),owner.user,bearer);assert.deepEqual((await snapshot(parent)).memberIds,[manual,nested].sort());
 await save(parent,input({draft,enabled:false}),'1');assert.deepEqual((await snapshot(parent)).memberIds,[manual]);
 assert.equal((await pool.query('SELECT count(*)::integer AS count FROM group_members WHERE group_id=$1',[parent.id])).rows[0].count,2);
});
test('source observation revisions isolate other tenants, survive retained deletion, remain exact and reject mixed read-committed observations',async()=>{
 const parent=await group('Stable own live revision');await person('Engineering');await save(parent);await sync(parent);const first=await snapshot(parent);
 const foreign=await activeCompany(database,schema,issuer);await creator.group({name:'Independent foreign group'},foreign.user,bearer);assert.equal((await snapshot(parent)).revision,first.revision);
 const extra=await group('Retained own group');const added=await snapshot(parent);assert.ok(BigInt(added.revision)>BigInt(first.revision));await groups.remove(extra.id,groupEtag(extra),owner.user,bearer);assert.ok(BigInt((await snapshot(parent)).revision)>BigInt(added.revision));
 const {GroupSnapshotStore}=require('../GroupSnapshotStore');let changed=false;const racing={transaction:operation=>database.transaction(client=>operation({query:async(sql,values)=>{
  const result=await client.query(sql,values);if(!changed&&sql.includes('ORDER BY membership.user_id')){changed=true;await save(parent,input({enabled:false}),'1');}return result;
 }}))};
 await assert.rejects(new GroupSnapshotStore(racing).snapshot(parent.id,null,{refreshReviews:false}),{status:409});assert.equal(changed,true);assert.deepEqual((await snapshot(parent)).memberIds,[]);
});
test('unavailable original live source evidence and receiver changes fail closed before a positive snapshot',async()=>{
 const parent=await group('Fail closed live source');await person('Engineering');await save(parent);await sync(parent);
 await pool.query('ALTER TABLE identity_company_group_rule_effect_outbox DISABLE TRIGGER company_group_rule_effect_before');
 await pool.query("UPDATE identity_company_group_rule_effect_outbox SET fingerprint=repeat('0',64)");
 await pool.query('ALTER TABLE identity_company_group_rule_effect_outbox ENABLE TRIGGER company_group_rule_effect_before');
 await assert.rejects(snapshot(parent),{code:'42501'});
});
test('nested sources inherit the latest valid alternative review deadline and revoke at expiry without a worker or renewed review',async()=>{
 const {GroupMembershipReviews,reviewTag}=require('../GroupMembershipReviews');const authority=new AuthorizationState(database);
 async function reviewer(role){const id=await person('Independent governance');const subject='live-reviewer-'+id;await pool.query('INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES($1,$2,$3)',[issuer,subject,id]);await pool.query('INSERT INTO identity_role_assignments(user_id,role,reason) VALUES($1,$2,$3)',[id,role,'Explicit independent live-rule review duty']);const state=await authority.state(issuer,subject);const now=Math.floor(Date.now()/1000);return {actor_type:'user',iss:issuer,sub:subject,roles:state.roles,identity_authorization:state.context,jti:randomUUID(),exp:now+3600,auth_time:now,amr:['pwd','otp'],mfa_authorization:{schemaVersion:1,userId:id,revision:'1',authTime:now,methods:['pwd','otp']}};}
 const manager=await reviewer('group-review-administrator');const voter=await reviewer('group-reviewer');const reviews=new GroupMembershipReviews(database,{revalidate:async()=>{}});
 const child=await group('Short reviewed child');const other=await group('Long reviewed child');const parent=await group('Alternative live witnesses');const own=await group('Own shorter review');const dynamic=await group('Independent dynamic witness');const userId=await person('Engineering');
 async function governed(collection,intervalSeconds){await reviews.create({groupId:collection.id,intervalSeconds,windowSeconds:60,reviewerUserIds:[voter.identity_authorization.userId],reason:'Actual independent live source review policy',acknowledgeEffects:true},manager,bearer);}
 async function approve(collection){const lease=(await pool.query('SELECT lease.id FROM identity_membership_review_leases lease JOIN identity_membership_origins origin ON origin.membership_id=lease.membership_id WHERE origin.group_id=$1 AND origin.user_id=$2',[collection.id,userId])).rows[0];const before=await reviews.get(lease.id,voter);return reviews.decide(lease.id,reviewTag(before),{decision:'retain',reason:'Actual independent bounded live source approval',acknowledgeScope:true},voter,bearer);}
 await governed(child,300);await governed(other,600);await governed(own,120);await save(child);await save(other);await sync(child);await sync(other);await approve(child);await approve(other);
 const draft={dynamic:null,childGroupIds:[child.id,other.id].sort(),excludedUserIds:[]};await save(parent,input({draft}));await sync(parent);await save(own,input({draft}));await sync(own);await approve(own);await save(dynamic,input({draft:{...draft,dynamic:input().draft.dynamic}}));await sync(dynamic);
 const first=await snapshot(parent);const longer=(await snapshot(other)).memberships[0].reviewDeadlineAt;const shorter=(await snapshot(child)).memberships[0].reviewDeadlineAt;const ownDeadline=(await pool.query('SELECT deadline_at FROM identity_membership_review_leases lease JOIN identity_membership_origins origin ON origin.membership_id=lease.membership_id WHERE origin.group_id=$1 AND origin.user_id=$2',[own.id,userId])).rows[0].deadline_at.toISOString();
 assert.equal(first.memberships[0].reviewDeadlineAt,longer);assert.equal((await snapshot(own)).memberships[0].reviewDeadlineAt,ownDeadline);assert.equal((await snapshot(dynamic)).memberships[0].reviewDeadlineAt,null);
 assert.equal((await rules.preview(parent.id,owner.user,bearer)).existing[0].validUntil,longer);
 const physical=(await pool.query('SELECT revision FROM groups WHERE id=$1',[parent.id])).rows[0].revision;
 const changeWorker=await appWorker();await changeWorker.automation.enqueue({id:randomUUID(),grantId:changeWorker.permission.id,action:'directory.groups.reconcile',format:'json',ruleId:parent.id,onChange:true},changeWorker.app,changeWorker.appBearer,true);await changedRun(changeWorker);
 const cutoffBefore=(await pool.query('SELECT identity_automation_change_identity($1,$2) AS source',[child.id,owner.receipt.tenantId])).rows[0].source.deadlineRevision;
 async function advance(timestamp){await pool.query("CREATE OR REPLACE FUNCTION identity_membership_review_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT '"+new Date(Date.parse(timestamp)+1).toISOString()+"'::timestamptz $$");}
 await advance(shorter);const alternate=await snapshot(parent);assert.deepEqual(alternate.memberIds,[userId]);assert.equal(alternate.memberships[0].reviewDeadlineAt,longer);assert.ok(BigInt(alternate.revision)>BigInt(first.revision));assert.deepEqual((await snapshot(own)).memberIds,[]);
 await advance(longer);const expired=await snapshot(parent);assert.deepEqual(expired.memberIds,[]);assert.ok(BigInt(expired.revision)>BigInt(alternate.revision));assert.deepEqual((await snapshot(dynamic)).memberIds,[userId]);
 assert.equal((await pool.query('SELECT revision FROM groups WHERE id=$1',[parent.id])).rows[0].revision,physical);assert.equal((await pool.query('SELECT count(*)::integer AS count FROM group_members WHERE user_id=$1',[userId])).rows[0].count,5);
 const cutoffAfter=(await pool.query('SELECT identity_automation_change_identity($1,$2) AS source',[child.id,owner.receipt.tenantId])).rows[0].source.deadlineRevision;assert.ok(BigInt(cutoffAfter)>BigInt(cutoffBefore));
 await changedRun(changeWorker);assert.equal((await pool.query('SELECT count(*)::integer AS count FROM group_members WHERE group_id=$1',[parent.id])).rows[0].count,0);
});
test('bounded live graph resolution never returns a partial positive when traversal is incomplete',async()=>{
 const child=await group('Bounded child');const parent=await group('Bounded parent');const root=await group('Bounded root');const userId=await person('Engineering');await save(child);await save(parent,input({draft:{dynamic:null,childGroupIds:[child.id],excludedUserIds:[]}}));await save(root,input({draft:{dynamic:null,childGroupIds:[parent.id],excludedUserIds:[]}}));await sync(child);await sync(parent);await sync(root);
 const membership=(await pool.query('SELECT membership_id FROM group_members WHERE group_id=$1 AND user_id=$2',[root.id,userId])).rows[0].membership_id;
 await assert.rejects(pool.query('SELECT * FROM identity_membership_rule_resolve($1,ARRAY[]::uuid[],2)',[membership]),{code:'42501'});
 assert.equal((await pool.query('SELECT remaining,deadline_at>clock_timestamp() AS allowed FROM identity_membership_rule_resolve($1,ARRAY[]::uuid[],3)',[membership])).rows[0].allowed,true);
 await pool.query("CREATE OR REPLACE FUNCTION identity_company_group_rule_dynamic(setting identity_company_group_rules,target UUID) RETURNS BOOLEAN LANGUAGE sql AS $$ SELECT true $$");
 await assert.rejects(snapshot(root),{code:'42501'});await assert.rejects(new AuthorizationState(database).state(issuer,owner.user.sub),{code:'42501'});
});
async function changedRun(worker,limit=8){const results=[];for(let index=0;index<limit;index++){const result=await worker.run();if(!result)return results;results.push(result);}assert.fail('Unchanged source did not converge without another change job');}
test('an explicitly subscribed real app materializes and removes attribute sources on change before a minute interval and survives human session expiry',async()=>{
 const parent=await group('Actual change-driven group');const userId=await person('Engineering');await save(parent);const worker=await appWorker();
 worker.automation.database={...database,transaction:(operation,options)=>database.transaction(async client=>{await client.query("SET LOCAL timezone='Pacific/Honolulu'");return operation(client);},options)};
 const input={id:randomUUID(),grantId:worker.permission.id,action:'directory.groups.reconcile',format:'json',ruleId:parent.id,onChange:true};
 const plan=(await worker.automation.enqueue(input,worker.app,worker.appBearer,true)).schedule;assert.equal(plan.onChange,true);assert.equal(plan.intervalSeconds,null);assert.equal(plan.lastSourceRevision,null);
 const started=Date.now();const first=await worker.run();assert.equal(first.job.status,'succeeded',JSON.stringify(first));assert.equal(first.job.scheduleId,plan.id);assert.equal(first.job.trigger.kind,'change');assert.equal(first.job.trigger.groupId,parent.id);
 assert.equal((await pool.query('SELECT count(*)::integer AS count FROM group_members WHERE group_id=$1',[parent.id])).rows[0].count,1);await changedRun(worker);
 const count=(await pool.query('SELECT count(*)::integer AS count FROM identity_automation_jobs WHERE schedule_id=$1',[plan.id])).rows[0].count;assert.equal(await worker.run(),null);
 await changeDepartment(userId,'Operations');owner.user.auth_time-=301;owner.user.mfa_authorization.authTime-=301;
 const removed=await worker.run();assert.equal(removed.job.status,'succeeded',JSON.stringify(removed));assert.equal((await pool.query('SELECT count(*)::integer AS count FROM group_members WHERE group_id=$1',[parent.id])).rows[0].count,0);await changedRun(worker);
 assert.ok(Date.now()-started<60000);assert.ok((await pool.query('SELECT count(*)::integer AS count FROM identity_automation_jobs WHERE schedule_id=$1',[plan.id])).rows[0].count>count);
 const retained=(await pool.query('SELECT source_checkpoint,source_job_id FROM identity_automation_schedules WHERE id=$1',[plan.id])).rows[0];const original=(await pool.query('SELECT event_source FROM identity_automation_jobs WHERE id=$1',[retained.source_job_id])).rows[0].event_source;assert.deepEqual(retained.source_checkpoint,original);
});
test('concurrent change workers retain one atomic event job per captured subscription revision and do not stack an unfinished job',async()=>{
 const parent=await group('Concurrent change subscription');await person('Engineering');await save(parent);const worker=await appWorker();
 const plan=(await worker.automation.enqueue({id:randomUUID(),grantId:worker.permission.id,action:'directory.groups.reconcile',format:'json',ruleId:parent.id,onChange:true},worker.app,worker.appBearer,true)).schedule;
 const results=await Promise.all([worker.run(),worker.run()]);assert.equal(results.filter(result=>result?.job.status==='succeeded').length,1);
 assert.equal((await pool.query('SELECT count(*)::integer AS count FROM identity_automation_jobs WHERE schedule_id=$1',[plan.id])).rows[0].count,1);
 await changedRun(worker);const stored=(await pool.query('SELECT revision,source_checkpoint FROM identity_automation_schedules WHERE id=$1',[plan.id])).rows[0];assert.ok(BigInt(stored.revision)>1n);assert.equal(await worker.run(),null);
});
test('missing original change checkpoint or canonical automation evidence rolls back both dispatch and subscription advancement',async()=>{
 const parent=await group('Atomic change receipt');await person('Engineering');await save(parent);const worker=await appWorker();
 const plan=(await worker.automation.enqueue({id:randomUUID(),grantId:worker.permission.id,action:'directory.groups.reconcile',format:'json',ruleId:parent.id,onChange:true},worker.app,worker.appBearer,true)).schedule;
 await pool.query(`CREATE FUNCTION fixture_omit_change_checkpoint() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.source_checkpoint IS DISTINCT FROM OLD.source_checkpoint THEN RETURN NULL;END IF;RETURN NEW;END;$$;
  CREATE TRIGGER aaa_fixture_omit_change_checkpoint BEFORE UPDATE ON identity_automation_schedules FOR EACH ROW EXECUTE FUNCTION fixture_omit_change_checkpoint()`);
 await assert.rejects(worker.run(),{code:'42501'});assert.equal((await pool.query('SELECT count(*)::integer AS count FROM identity_automation_jobs WHERE schedule_id=$1',[plan.id])).rows[0].count,0);assert.equal((await pool.query('SELECT source_checkpoint FROM identity_automation_schedules WHERE id=$1',[plan.id])).rows[0].source_checkpoint,null);
 await pool.query('DROP TRIGGER aaa_fixture_omit_change_checkpoint ON identity_automation_schedules');assert.equal((await worker.run()).job.status,'succeeded');
});
