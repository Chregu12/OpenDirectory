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
    try { await pool.query(fs.readFileSync(path.join(migrations, file), 'utf8')); } catch (error) { throw new Error(file + ': ' + error.message + '\n' + error.where); }
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

test('an actual group link uses an immutable license-only blueprint and assigns its members from the finite pool', async () => {
  const product = await catalog(2); const users = [randomUUID(), randomUUID()]; const rule = await link(product.id, users);
  const preview = await service.preview(rule.id, user, bearer); assert.equal(preview.pendingMembers, 2);
  const result = await sync(rule); assert.equal(result.results.filter(row => row.status === 'assigned').length, 2); assert.equal(result.nextCursor, null); assert.equal(await used(product.id), 2);
  assert.equal((await pool.query('SELECT count(*)::int AS n FROM company_license_group_effects')).rows[0].n, 2);
  assert.equal((await sync(rule)).results.every(row => row.status === 'retained'), true); assert.equal(await used(product.id), 2);
  const release = (await pool.query('SELECT draft FROM company_blueprint_versions WHERE blueprint_id=$1 AND version=1', [rule.blueprintId])).rows[0];
  assert.deepEqual(release.draft.configurations, []); assert.deepEqual(release.draft.appPoolIds, [product.id]);
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
