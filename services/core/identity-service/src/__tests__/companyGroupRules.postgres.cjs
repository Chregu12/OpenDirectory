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
async function person(department, title = '') {
 const id = randomUUID(); await pool.query('INSERT INTO users(id,username,email,department,title) VALUES($1,$2,$3,$4,$5)', [id, 'employee-' + id, id + '@test.invalid', department, title]);
 await adoptTenant(database, schema, owner.receipt.tenantId, [{ kind: 'user', resourceId: id }]); return id;
}
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
 await pool.query(fs.readFileSync(path.join(__dirname,'../../migrations/050_company_group_rules.sql'),'utf8'));
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
});
test('nested rules use effective canonical child membership and remain ordinary actual memberships in each parent', async () => {
 const child = await group('Dynamic child'); const parent = await group('Nested parent'); const grandparent = await group('Nested grandparent'); const userId = await person('Engineering');
 await save(child); await save(parent, input({ draft: { dynamic: null, childGroupIds: [child.id], excludedUserIds: [] } })); await save(grandparent, input({ draft: { dynamic: null, childGroupIds: [parent.id], excludedUserIds: [] } }));
 assert.equal((await rules.preview(parent.id, owner.user, bearer)).desired.length, 0); await sync(child); await sync(parent); await sync(grandparent);
 for (const collection of [child, parent, grandparent]) assert.equal((await pool.query('SELECT count(*)::integer AS count FROM group_members WHERE group_id=$1 AND user_id=$2', [collection.id, userId])).rows[0].count, 1);
 await save(child, input({ enabled: false }), '1'); await sync(child); await sync(parent); await sync(grandparent);
 assert.equal((await pool.query('SELECT count(*)::integer AS count FROM group_members WHERE user_id=$1', [userId])).rows[0].count, 0);
});
