'use strict';
const { test, beforeEach, afterEach, after } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const fs = require('node:fs'); const path = require('node:path'); const { Pool } = require('pg');
const { CompanyLicenses } = require('../CompanyLicenses'); const { CompanyBlueprints } = require('../../CompanyBlueprints');
const { CompanyBlueprintAssignments } = require('../CompanyBlueprintAssignments'); const { CompanyLicenseGroups } = require('../CompanyLicenseGroups');
const { LicenseAllocator } = require('../LicenseAllocator'); const { normalizeSnapshot } = require('../GroupSnapshotClient');
const administration = new Pool({ connectionString: process.env.LICENSE_TEST_DATABASE_URL, max: 1 });
const migrations = path.join(__dirname, '../../db/migrations'); const reason = 'Configure actual own group based license allocation'; const bearer = 'Bearer actual.group.owner';
let pool, database, schema, user, source, companies, service, groups, members, eligibility, snapshotCalls, changeAt;
beforeEach(async () => {
  schema = 'company_groups_' + randomUUID().replaceAll('-', ''); await administration.query('CREATE SCHEMA ' + schema);
  const url = new URL(process.env.LICENSE_TEST_DATABASE_URL); url.searchParams.set('options', '-c search_path=' + schema + ',public -c timezone=UTC'); pool = new Pool({ connectionString: url.toString(), max: 8 });
  for (const file of fs.readdirSync(migrations).filter(file => file.endsWith('.sql')).sort()) {
    const sql=fs.readFileSync(path.join(migrations,file),'utf8');
    try { await pool.query(sql); } catch (error) { const position=Number(error.internalPosition||error.position||1)-1;throw new Error(file+': '+error.message+' near '+JSON.stringify((error.internalQuery||sql).slice(Math.max(0,position-120),position+120))+'\n'+error.where); }
  }
  const now = Math.floor(Date.now() / 1000); const actor = randomUUID();
  user = { actor_type: 'user', token_use: 'access', iss: 'https://groups.native', sub: 'original-owner', jti: randomUUID(), exp: now + 3600, auth_time: now,
    identity_authorization: { userId: actor, revision: '1', linkRevision: '1', rolesRevision: 'a'.repeat(64) }, amr: ['pwd', 'otp'],
    mfa_authorization: { schemaVersion: 1, userId: actor, revision: '1', authTime: now, methods: ['pwd', 'otp'] } };
  source = { schemaVersion: 1, issuer: user.iss, subject: user.sub, tokenId: user.jti, expiresAt: user.exp, context: user.identity_authorization,
    tenant: { id: randomUUID(), version: '1', generation: '1' }, actorUserId: actor, permissions: ['company.apps.read', 'company.apps.create', 'company.apps.assign'], validUntil: now + 300, target: null };
  database = { query: (...args) => pool.query(...args), getClient: () => pool.connect() }; eligibility = new Map(); members = new Map(); snapshotCalls = 0; changeAt = Infinity;
  const applicationAuthority = { read: async (_bearer, _user, userId = null) => structuredClone({ ...source, target: userId ? { id: userId, revision: '1', eligibilityRevision: eligibility.get(userId) || '1', enabled: true, deleted: false } : null }) };
  const assignmentAuthority = { read: async (...args) => ({ ...await applicationAuthority.read(...args), companyBlueprintAssignmentsProtocol: 1, permissions: ['company.blueprints.assignments.read', 'company.blueprints.assign'] }) };
  const blueprintAuthority = { read: async () => { const { target, ...base } = await applicationAuthority.read(); return { ...base, companyBlueprintProtocol: 1, permissions: ['company.blueprints.read', 'company.blueprints.manage', 'company.blueprints.publish'] }; } };
  const allocator = new LicenseAllocator(database); companies = new CompanyLicenses(allocator, { authority: applicationAuthority });
  groups = { snapshot: async (groupId, auth, company) => {
    assert.equal(auth, bearer); assert.equal(company, true); snapshotCalls++;
    if (!members.has(groupId)) throw Object.assign(new Error('Foreign group'), { status: 404 });
    const users = members.get(groupId); const observed = new Date();
    return normalizeSnapshot({ schemaVersion: 3, groupId, name: 'Actual license group', revision: snapshotCalls >= changeAt ? '2' : '1', deleted: false,
      memberIds: [...users].sort(), inactiveMemberIds: [], unresolvedMemberIds: [], viewerUserId: actor, viewerEnabled: true, observedAt: observed.toISOString(),
      validUntil: new Date(observed.getTime() + 300000).toISOString(), sourceAuthorization: null,
      memberships: [...users].sort().map(userId => ({ userId, membershipId: userId, eligibilityRevision: eligibility.get(userId) || '1', reviewDeadlineAt: null })) }, groupId);
  } };
  service = new CompanyLicenseGroups(companies, { groups, blueprints: new CompanyBlueprints(database, { authority: blueprintAuthority, applicationAuthority }),
    assignments: new CompanyBlueprintAssignments(database, { allocator, authority: assignmentAuthority, applicationAuthority }) });
});
afterEach(async () => { await pool.end(); await administration.query('DROP SCHEMA IF EXISTS ' + schema + ' CASCADE'); });
after(async () => administration.end());
const catalog = (seats = 3) => companies.create({ name: 'Own app', vendor: 'Own vendor', description: '', totalSeats: seats, reason }, user, bearer);
async function link(poolId, userIds = []) {
  const groupId = randomUUID(); members.set(groupId, new Set(userIds)); const key = randomUUID();
  const result = await service.link({ groupId, poolId, reason, confirm: true }, key, user, bearer); return { ...result.rule, key };
}
const sync = (rule, groupRevision = '1') => service.sync(rule.id, { groupRevision, cursor: null, reason, confirm: true }, user, bearer);
const used = async poolId => (await pool.query('SELECT used_seats FROM license_catalog WHERE id=$1', [poolId])).rows[0].used_seats;

function machine(rule) {
  let retryCount = 0;
  const now = Math.floor(Date.now() / 1000); const grantId = randomUUID(); const jobId = randomUUID(); const leaseToken = randomUUID();
  const app = { actor_type: 'application', token_use: 'access', iss: user.iss, sub: 'actual-license-app', client_id: 'actual-license-app', client_revision: '1', jti: randomUUID(), exp: now + 3600, scope: 'company.automation', permissions: ['company.automation'] };
  const authority = { read: async (_auth, _app, userId = null) => ({ schemaVersion: 1, companyLicenseAutomationProtocol: 1, kind: 'application', issuer: app.iss, subject: app.sub, tokenId: app.jti, expiresAt: app.exp,
    clientRevision: app.client_revision, tenant: source.tenant, grantId, jobId, leaseToken, ruleId: rule.id, retryCount, validUntil: now + 45, permissions: ['licenses.groups.reconcile'],
    target: userId ? { id: userId, revision: '1', eligibilityRevision: eligibility.get(userId) || '1', enabled: true, deleted: false } : null,
    group: { schemaVersion: 3, groupId: rule.groupId, name: 'Actual license group', revision: '1', deleted: false, memberIds: [...members.get(rule.groupId)].sort(), inactiveMemberIds: [], unresolvedMemberIds: [],
      memberships: [...members.get(rule.groupId)].sort().map(id => ({ userId: id, membershipId: id, eligibilityRevision: eligibility.get(id) || '1', reviewDeadlineAt: null })) } }) };
  const allocator = companies.allocator;
  const worker = new CompanyLicenseGroups(new CompanyLicenses(allocator, { authority }), { assignments: new CompanyBlueprintAssignments(database, { allocator, authority, applicationAuthority: authority }),
    groups: { machineSnapshot: auth => authority.read(auth, app) }, correlationId: jobId });
  const context = { grantId, jobId, leaseToken, ruleId: rule.id };
  const factory = selected => ({ read: async (auth, actor, userId = null) => {
    const value = await authority.read(auth, actor, userId); if (selected.groupId === null) value.group = null; return value;
  } });
  return { app, grantId, jobId, leaseToken, authority, worker, context, factory, nextRetry: () => retryCount++, sync: () => worker.sync(rule.id, { groupRevision: '1', cursor: null, reason, confirm: true }, app, 'Bearer actual-machine') };
}

test('a typed app delegation allocates and removes the original group source without human identity or MFA and retains actual client provenance', async () => {
  const product = await catalog(1); const userId = randomUUID(); const rule = await link(product.id, [userId]); const runtime = machine(rule);
  const proof = await runtime.authority.read(); for (const field of ['context', 'actorUserId', 'auth_time', 'mfa_authorization', 'roles']) assert.equal(Object.hasOwn(proof, field), false);
  assert.equal((await runtime.sync()).results[0].status, 'assigned'); assert.equal(await used(product.id), 1);
  const binding = (await pool.query('SELECT company_blueprint_assignment_view(binding) AS value FROM company_blueprint_user_assignments binding WHERE blueprint_id=$1', [rule.blueprintId])).rows[0].value;
  assert.equal(binding.actorUserId, null); assert.deepEqual(binding.actor, { kind: 'application', id: runtime.grantId, clientId: runtime.app.client_id, clientRevision: '1' });
  const actual = (await pool.query('SELECT actor_user_id,source,command FROM company_blueprint_assignment_operations WHERE assignment_id=$1', [binding.id])).rows[0];
  assert.equal(actual.actor_user_id, runtime.grantId); assert.equal(actual.source.subject, runtime.app.client_id); assert.equal(actual.command.correlationId, runtime.jobId);
  const history = await companies.history(product.id, {}, user, bearer); const event = history.events.find(item => item.type === 'app.license.source.assigned');
  assert.equal(event.actorUserId, null); assert.deepEqual(event.actor, binding.actor); assert.equal(event.correlationId, runtime.jobId);
  await assert.rejects(companies.assignments(product.id, {}, user, bearer), error => error.message === 'upgrade_required');
  members.get(rule.groupId).delete(userId); assert.equal((await runtime.sync()).results[0].status, 'removed'); assert.equal(await used(product.id), 0);
});
test('the app run journals all 27 targets across restart and its repeated final observation does not allocate another seat',async()=>{
 const product=await catalog(27);const rule=await link(product.id,Array.from({length:27},()=>randomUUID()));const runtime=machine(rule);
 const {CompanyLicenseAutomation}=require('../CompanyLicenseAutomation');const service=()=>new CompanyLicenseAutomation(database,{allocator:companies.allocator,authority:runtime.factory});
 const first=await service().step(runtime.context,runtime.app,'Bearer actual-machine');assert.equal(first.finished,false);assert.equal(first.progress.completed,25);assert.equal(first.progress.total,27);
 const second=await service().step(runtime.context,runtime.app,'Bearer actual-machine');assert.equal(second.finished,true);assert.equal(second.hasBlocked,false);assert.equal(second.results.length,27);assert.equal(await used(product.id),27);
 assert.deepEqual(await service().step(runtime.context,runtime.app,'Bearer actual-machine'),second);
 assert.equal((await pool.query('SELECT count(*)::int AS count FROM company_license_automation_pages')).rows[0].count,2);
 assert.equal((await pool.query('SELECT count(*)::int AS count FROM company_license_automation_outbox')).rows[0].count,3);
 await assert.rejects(pool.query('DELETE FROM company_license_automation_pages'),{code:'42501'});
});

test('a full pool produces a real partial app report and a new retry can use a seat freed by the group itself', async () => {
 const product = await catalog(1); const users = [randomUUID(), randomUUID()].sort(); const rule = await link(product.id, users); const runtime = machine(rule);
 const { CompanyLicenseAutomation } = require('../CompanyLicenseAutomation'); const driver = () => new CompanyLicenseAutomation(database, { allocator: companies.allocator, authority: runtime.factory });
 const partial = await driver().step(runtime.context, runtime.app, 'Bearer actual-machine');
 assert.equal(partial.finished, true); assert.equal(partial.hasBlocked, true); assert.equal(partial.progress.blocked, 1); assert.equal(await used(product.id), 1);
 assert.deepEqual(partial.results.map(item => item.status), ['assigned', 'blocked']);
 members.get(rule.groupId).delete(users[0]); runtime.nextRetry();
 let outcome; for (let count = 0; count < 3; count++) { outcome = await driver().step(runtime.context, runtime.app, 'Bearer actual-machine'); if (outcome.finished) break; }
 assert.equal(outcome.finished, true); assert.equal(outcome.hasBlocked, false); assert.equal(outcome.progress.retryCount, 1); assert.equal(await used(product.id), 1);
 assert.equal((await pool.query("SELECT user_id FROM company_blueprint_user_assignments WHERE blueprint_id=$1 AND status='active'", [rule.blueprintId])).rows[0].user_id, users[1]);
 assert.equal((await pool.query('SELECT count(*)::int AS count FROM company_license_automation_pages WHERE retry_count=0')).rows[0].count, 1);
});

test('a lost page acknowledgement resumes original receipts and corrupt retained outbox evidence stops further app work', async () => {
 const product = await catalog(2); const rule = await link(product.id, [randomUUID(), randomUUID()]); const runtime = machine(rule);
 const { CompanyLicenseAutomation } = require('../CompanyLicenseAutomation'); const driver = new CompanyLicenseAutomation(database, { allocator: companies.allocator, authority: runtime.factory });
 const journal = driver.journal.bind(driver); let calls = 0;
 driver.journal = async (...args) => { const value = await journal(...args); if (++calls === 2) throw new Error('Connection lost after real page commit'); return value; };
 await assert.rejects(driver.step(runtime.context, runtime.app, 'Bearer actual-machine'), /Connection lost/); assert.equal(await used(product.id), 2);
 const recovered = await new CompanyLicenseAutomation(database, { allocator: companies.allocator, authority: runtime.factory }).step(runtime.context, runtime.app, 'Bearer actual-machine');
 assert.equal(recovered.finished, true); assert.equal(await used(product.id), 2); assert.equal((await pool.query('SELECT count(*)::int AS count FROM company_license_automation_pages')).rows[0].count, 1);
 await pool.query('ALTER TABLE company_license_automation_outbox DISABLE TRIGGER USER');
 await pool.query("UPDATE company_license_automation_outbox SET fingerprint=repeat('0',64) WHERE page=1");
 await pool.query('ALTER TABLE company_license_automation_outbox ENABLE TRIGGER USER');
 await assert.rejects(driver.step(runtime.context, runtime.app, 'Bearer actual-machine'), { status: 503 }); assert.equal(await used(product.id), 2);
});

test('an app journal whose original lease expires before physical commit rolls back its cycle and pending receipt', async () => {
 const product = await catalog(1); const rule = await link(product.id); const runtime = machine(rule); const deadline = Math.floor(Date.now() / 1000) + 2;
 const { CompanyLicenseAutomation } = require('../CompanyLicenseAutomation');
 const authority = context => { const original = runtime.factory(context); return { read: async (...args) => ({ ...await original.read(...args), validUntil: deadline }) }; };
 const driver = new CompanyLicenseAutomation(database, { allocator: companies.allocator, authority }); const journal = driver.journal.bind(driver);
 driver.journal = (...args) => { const operation = args.pop(); return journal(...args, async client => { const value = await operation(client); await new Promise(resolve => setTimeout(resolve, Math.max(1, deadline * 1000 - Date.now() + 50))); return value; }); };
 await assert.rejects(driver.step(runtime.context, runtime.app, 'Bearer actual-machine'), { code: '42501' });
 assert.equal((await pool.query('SELECT count(*)::integer AS count FROM company_license_automation_cycles')).rows[0].count, 0);
 assert.equal((await pool.query('SELECT count(*)::integer AS count FROM company_license_automation_outbox')).rows[0].count, 0); assert.equal(await used(product.id), 0);
});

test('missing machine journal guards and malformed retained machine sources fail closed before allocations', async () => {
 const product = await catalog(2); const rule = await link(product.id, [randomUUID(), randomUUID()]); const runtime = machine(rule); const proof = await runtime.authority.read();
 assert.equal((await pool.query('SELECT company_blueprint_assignment_machine_source($1::jsonb) AS valid', [proof])).rows[0].valid, true);
 for (const modified of [{ ...proof, retryCount: 0.5 }, { ...proof, context: {} }, { ...proof, validUntil: Math.floor(Date.now() / 1000) - 1 }, { ...proof, group: { ...proof.group, memberships: proof.group.memberships.map(item => ({ ...item, membershipId: proof.group.memberships[0].membershipId })) } }]) {
  assert.equal((await pool.query('SELECT company_blueprint_assignment_machine_source($1::jsonb) AS valid', [modified])).rows[0].valid, false);
 }
 await pool.query('ALTER TABLE company_license_automation_pages DISABLE TRIGGER company_license_automation_commit');
 const { CompanyLicenseAutomation } = require('../CompanyLicenseAutomation');
 await assert.rejects(new CompanyLicenseAutomation(database, { allocator: companies.allocator, authority: runtime.factory }).step(runtime.context, runtime.app, 'Bearer actual-machine'), { code: '42501' });
 assert.equal(await used(product.id), 0);
});

test('an actual group link uses an immutable license-only blueprint and assigns its members from the finite pool', async () => {
  const product = await catalog(2); const users = [randomUUID(), randomUUID()]; const rule = await link(product.id, users);
  const preview = await service.preview(rule.id, user, bearer); assert.equal(preview.pendingMembers, 2);
  const result = await sync(rule); assert.equal(result.results.filter(row => row.status === 'assigned').length, 2); assert.equal(result.nextCursor, null); assert.equal(await used(product.id), 2);
  assert.equal((await pool.query('SELECT count(*)::int AS n FROM company_license_group_effects')).rows[0].n, 2);
  assert.equal((await sync(rule)).results.every(row => row.status === 'retained'), true); assert.equal(await used(product.id), 2);
  const release = (await pool.query('SELECT draft FROM company_blueprint_versions WHERE blueprint_id=$1 AND version=1', [rule.blueprintId])).rows[0];
  assert.deepEqual(release.draft.configurations, []); assert.deepEqual(release.draft.appPoolIds, [product.id]);
});
test('original group evidence remains readable across PostgreSQL session timezones without rewriting its timestamps', async () => {
 const product = await catalog(1); const rule = await link(product.id); const client = await pool.connect();
 try {
  await client.query("SET timezone='Europe/Zurich'"); assert.equal((await service.rule(client, rule.id, source)).id, rule.id);
  const original = (await client.query('SELECT result FROM company_license_group_events WHERE rule_id=$1', [rule.id])).rows[0].result;
  assert.notEqual(original.created_at, (await client.query('SELECT to_jsonb(actual) AS value FROM company_license_groups actual WHERE id=$1', [rule.id])).rows[0].value.created_at);
 } finally { await client.query("SET timezone='UTC'"); client.release(); }
});
test('multiple group sources and a direct grant consume one seat, and removing a group preserves the other origins', async () => {
  let product = await catalog(1); const userId = randomUUID();
  product = await companies.assign(product.id, { userId, reason, confirm: true }, `"company-pool-${product.id}-${product.revision}"`, user, bearer);
  const first = await link(product.id, [userId]); const second = await link(product.id, [userId]); await sync(first); await sync(second);
  assert.equal(await used(product.id), 1); assert.equal((await pool.query('SELECT count(*)::int AS n FROM license_assignment_sources WHERE license_id=$1', [product.id])).rows[0].n, 3);
  members.set(first.groupId, new Set()); assert.equal((await sync(first)).results[0].status, 'removed'); assert.equal(await used(product.id), 1);
  members.set(second.groupId, new Set()); await sync(second); assert.equal(await used(product.id), 1);
  assert.deepEqual((await pool.query('SELECT source_type FROM license_assignment_sources WHERE license_id=$1', [product.id])).rows.map(row => row.source_type), ['direct']);
});
test('pool exhaustion reports blocked members and never oversells; a later sync can retry available capacity', async () => {
  const product = await catalog(1); const rule = await link(product.id, [randomUUID(), randomUUID()]);
  const result = await sync(rule); assert.equal(result.hasBlocked, true); assert.equal(result.results.filter(row => row.status === 'assigned').length, 1);
  assert.equal(result.results.filter(row => row.status === 'blocked').length, 1); assert.equal(await used(product.id), 1);
  const assigned = result.results.find(row => row.status === 'assigned').userId; members.get(rule.groupId).delete(assigned);
  await sync(rule); await sync(rule); assert.equal(await used(product.id), 1);
});
test('unlinking retains configuration history, removes only this group source and supports migration replay', async () => {
  const product = await catalog(1); const rule = await link(product.id, [randomUUID()]); await sync(rule);
  const operation = randomUUID();
  const result = await service.unlink(rule.id, { reason, confirm: true }, `"company-license-group-${rule.id}-1"`, operation, user, bearer);
  assert.deepEqual(await service.unlink(rule.id, { reason, confirm: true }, `"company-license-group-${rule.id}-1"`, operation, user, bearer), result);
  assert.equal(result.rule.status, 'unlinked'); await sync(rule, null); assert.equal(await used(product.id), 0);
  await pool.query(fs.readFileSync(path.join(migrations, '028_company_license_groups.sql'), 'utf8'));
  assert.equal((await service.list({ groupId: rule.groupId }, user, bearer)).rules[0].status, 'unlinked');
  await assert.rejects(pool.query('DELETE FROM company_license_group_events'), { code: '42501' });
  for(const table of ['company_license_groups','company_license_group_events','company_license_group_outbox','company_license_group_effects'])await assert.rejects(pool.query('TRUNCATE '+table+' CASCADE'),{code:'42501'});
});
test('foreign pools/groups and a changed source revision cannot create a member allocation', async () => {
  const product = await catalog(1); const groupId = randomUUID();
  await assert.rejects(service.link({ groupId, poolId: product.id, reason, confirm: true }, randomUUID(), user, bearer), { status: 404 });
  members.set(groupId, new Set()); await assert.rejects(service.link({ groupId, poolId: randomUUID(), reason, confirm: true }, randomUUID(), user, bearer), { status: 404 });
  const rule = await link(product.id, [randomUUID()]); await assert.rejects(service.sync(rule.id, { groupRevision: '9', cursor: null, reason, confirm: true }, user, bearer), { status: 412 });
  snapshotCalls = 0; changeAt = 3; await assert.rejects(sync(rule), { status: 412 }); assert.equal(await used(product.id), 0);
});
test('missing receiving guards and raw linkage changes cannot be acknowledged', async () => {
  const product = await catalog(1); const rule = await link(product.id, []);
  await assert.rejects(pool.query("UPDATE company_license_groups SET status='unlinked',revision=2 WHERE id=$1", [rule.id]), { code: '42501' });
  await pool.query('ALTER TABLE company_license_groups DISABLE TRIGGER company_license_group_commit');
  await assert.rejects(service.list({}, user, bearer), { code: '42501' });
});
test('bounded cursor pages cover the complete group and a new eligibility generation replaces only its original source', async () => {
  const product=await catalog(26); const users=Array.from({length:26},()=>randomUUID()).sort(); const rule=await link(product.id,users);
  const first=await sync(rule);assert.equal(first.results.length,25);assert.equal(first.nextCursor,users[24]);
  const second=await service.sync(rule.id,{groupRevision:'1',cursor:first.nextCursor,reason,confirm:true},user,bearer);assert.equal(second.results.length,1);assert.equal(second.nextCursor,null);assert.equal(await used(product.id),26);
  eligibility.set(users[0],'2');const result=await sync(rule);assert.equal(result.results[0].status,'assigned');assert.equal(await used(product.id),26);
  const bindings=(await pool.query('SELECT status,eligibility_revision FROM company_blueprint_user_assignments WHERE blueprint_id=$1 AND user_id=$2 ORDER BY created_at',[rule.blueprintId,users[0]])).rows;
  assert.deepEqual(bindings.map(row=>[row.status,String(row.eligibility_revision)]),[['removed','1'],['active','2']]);
});
test('concurrent independent group reconciliations never oversell the same finite pool', async () => {
  const product=await catalog(1);const first=await link(product.id,[randomUUID()]);const second=await link(product.id,[randomUUID()]);
  const results=await Promise.allSettled([sync(first),sync(second)]);assert.equal(await used(product.id),1);
  assert.equal(results.filter(result=>result.status==='fulfilled'&&result.value.results.some(row=>row.status==='assigned')).length,1);
  for(const result of results)if(result.status==='rejected')assert.equal(result.reason.status,412);
});
test('an effect whose deadline passes before physical COMMIT rolls back the source, allocation and receipt together', async () => {
  const product=await catalog(1);const rule=await link(product.id,[randomUUID()]);const original=database.getClient;
  database.getClient=async()=>{const client=await original();let effect=false;return{release:()=>client.release(),query:async(sql,values)=>{
    if(typeof sql==='string'&&sql.includes('INSERT INTO company_license_group_effects')){values=[...values];values[5]=new Date(Date.now()+120).toISOString();effect=true;}
    if(sql==='COMMIT'&&effect)await client.query('SELECT pg_sleep(0.2)');return client.query(sql,values);
  }};};
  await assert.rejects(sync(rule),error=>error.status===503&&error.cause?.code==='42501');assert.equal(await used(product.id),0);
  assert.equal((await pool.query('SELECT count(*)::int AS n FROM company_license_group_effects')).rows[0].n,0);
  assert.equal((await pool.query("SELECT count(*)::int AS n FROM company_blueprint_user_assignments WHERE status='active'")).rows[0].n,0);
});
