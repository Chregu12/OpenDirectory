'use strict';

const { test, beforeEach, afterEach, after } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { Pool } = require('pg');
const { CompanyBlueprintAssignments } = require('../CompanyBlueprintAssignments');
const { CompanyLicenses } = require('../CompanyLicenses');
const { CompanyBlueprints } = require('../../CompanyBlueprints');
const { LicenseAllocator } = require('../LicenseAllocator');
const administration = new Pool({ connectionString: process.env.LICENSE_TEST_DATABASE_URL, max: 1 });
const directory = path.join(__dirname, '../../db/migrations');
const bearer = 'Bearer own.blueprint.assignment'; const reason = 'Explicitly reviewed immutable own blueprint assignment';
let schema; let pool; let database; let source; let application; let user; let target; let service; let companies; let blueprints;
beforeEach(async () => {
  schema = 'company_assignment_' + randomUUID().replaceAll('-', ''); await administration.query('CREATE SCHEMA ' + schema);
  const url = new URL(process.env.LICENSE_TEST_DATABASE_URL); url.searchParams.set('options', '-c search_path=' + schema + ',public -c timezone=UTC'); pool = new Pool({ connectionString: url.toString(), max: 8 });
  for (const filename of fs.readdirSync(directory).filter(filename => filename.endsWith('.sql')).sort()) {
    try { await pool.query(fs.readFileSync(path.join(directory, filename), 'utf8')); }
    catch (error) { const position = Number(error.internalPosition || error.position || 1) - 1; throw new Error(filename + ': ' + error.message + ' at ' + position + ' near ' + JSON.stringify((error.internalQuery || '').slice(Math.max(0, position - 120), position + 120)) + ' ' + error.where); }
  }
  const now = Math.floor(Date.now() / 1000); const actor = randomUUID(); target = { id: randomUUID(), revision: '1', eligibilityRevision: '1', enabled: true, deleted: false };
  user = { actor_type: 'user', token_use: 'access', iss: 'https://assignment.native', sub: 'actual-owner', jti: randomUUID(), exp: now + 3600, auth_time: now, identity_authorization: { userId: actor, revision: '1', linkRevision: '1', rolesRevision: 'a'.repeat(64) }, amr: ['pwd', 'otp'], mfa_authorization: { schemaVersion: 1, userId: actor, revision: '1', authTime: now, methods: ['pwd', 'otp'] } };
  source = { schemaVersion: 1, companyBlueprintAssignmentsProtocol: 1, issuer: user.iss, subject: user.sub, tokenId: user.jti, expiresAt: user.exp, context: user.identity_authorization, tenant: { id: randomUUID(), version: '1', generation: '1' }, actorUserId: actor, permissions: ['company.blueprints.assignments.read', 'company.blueprints.assign'], validUntil: now + 300, target: null };
  const { companyBlueprintAssignmentsProtocol, ...base } = source; application = { ...base, permissions: ['company.apps.read', 'company.apps.create', 'company.apps.assign'], target: null };
  database = { query: (...args) => pool.query(...args), getClient: () => pool.connect() };
  const authority = { read: async (_bearer, _user, userId = null) => structuredClone({ ...source, target: userId ? { ...target, id: userId } : null }) };
  const applicationAuthority = { read: async (_bearer, _user, userId = null) => structuredClone({ ...application, target: userId ? { ...target, id: userId } : null }) };
  service = new CompanyBlueprintAssignments(database, { authority, applicationAuthority }); companies = new CompanyLicenses(new LicenseAllocator(database), { authority: applicationAuthority });
  blueprints = new CompanyBlueprints(database, { authority: { read: async () => { const { companyBlueprintAssignmentsProtocol, target: ignored, ...value } = source; return { ...structuredClone(value), companyBlueprintProtocol: 1, permissions: ['company.blueprints.read', 'company.blueprints.manage', 'company.blueprints.publish'] }; } }, applicationAuthority });
});
afterEach(async () => { await pool.end(); await administration.query('DROP SCHEMA IF EXISTS ' + schema + ' CASCADE'); });
after(async () => administration.end());
async function createPool(totalSeats = 2) { return companies.create({ name: 'Own finite app ' + randomUUID(), vendor: 'Own vendor', description: '', totalSeats, reason }, user, bearer); }
async function release(poolIds = [], minutes = 5, configurationId = randomUUID()) {
  const id = randomUUID(); const draft = { name: 'Pinned blueprint', description: '', platform: 'all', configurations: [{ id: configurationId, type: 'screen_lock', name: 'Lock', payloadJson: JSON.stringify({ minutes, requirePassword: true }) }], appPoolIds: poolIds };
  await blueprints.change('created', id, { id, draft, reason, confirm: true }, undefined, randomUUID(), user, bearer);
  await blueprints.change('published', id, { reason, confirm: true }, `"company-blueprint-${id}-1"`, randomUUID(), user, bearer); return id;
}
async function assign(blueprintId, id = randomUUID(), operation = randomUUID()) {
  const preview = await service.preview({ userId: target.id, blueprintId, version: 1 }, user, bearer);
  const input = { id, userId: target.id, blueprintId, version: 1, eligibilityRevision: preview.eligibilityRevision, pools: preview.pools.map(({ poolId, poolRevision }) => ({ poolId, poolRevision })), reason, confirm: true };
  return { input, operation, result: await service.change('assigned', undefined, input, undefined, operation, user, bearer) };
}
async function snapshots() { const result = {}; for (const relation of ['license_catalog', 'license_assignments', 'license_assignment_sources', 'license_grants', 'license_grant_events', 'license_company_commands', 'license_company_events', 'company_blueprint_user_assignments', 'company_blueprint_assignment_operations']) result[relation] = (await pool.query('SELECT to_jsonb(actual) AS value FROM ' + relation + ' actual ORDER BY to_jsonb(actual)::text')).rows; return result; }
test('actual migrations and local immutable zero-app user assignment have canonical timestamps and retained source proof', async () => {
  const id = await release(); const assigned = await assign(id); assert.equal(assigned.result.outcome, 'applied'); const detail = await service.get(assigned.input.id, user, bearer);
  assert.equal(detail.assignment.status, 'active'); assert.equal(new Date(detail.assignment.createdAt).toISOString(), detail.assignment.createdAt); assert.equal(detail.assignment.revision, '1'); assert.deepEqual(assigned.result.pools, []);
});
test('two blueprint sources consume one real seat and removal preserves the other source and projection', async () => {
  const app = await createPool(); const first = await assign(await release([app.id])); const second = await assign(await release([app.id]));
  assert.equal((await pool.query('SELECT used_seats FROM license_catalog WHERE id=$1', [app.id])).rows[0].used_seats, 1);
  assert.equal((await pool.query('SELECT count(*)::integer AS total FROM license_grants WHERE license_id=$1 AND kind=$2', [app.id, 'direct'])).rows[0].total, 2);
  const preview = await service.removalPreview(first.input.id, user, bearer); const result = await service.change('removed', first.input.id, { userId: target.id, eligibilityRevision: target.eligibilityRevision, pools: preview.pools, reason, confirm: true }, `"company-blueprint-assignment-${first.input.id}-1"`, randomUUID(), user, bearer);
  assert.equal(result.pools[0].effectiveAssignmentRetained, true); assert.equal(result.pools[0].seatReleased, false); assert.equal((await service.get(second.input.id, user, bearer)).assignment.status, 'active');
});
test('a later full pool rolls back every earlier source, grant, binding, counter and receipt', async () => {
  const first = await createPool(1); const full = await createPool(1); const saved = target.id; target.id = randomUUID(); await assign(await release([full.id])); target.id = saved;
  const blueprintId = await release([first.id, full.id]); const preview = await service.preview({ userId: target.id, blueprintId, version: 1 }, user, bearer); const before = await snapshots();
  await assert.rejects(service.change('assigned', null, { id: randomUUID(), userId: target.id, blueprintId, version: 1, eligibilityRevision: target.eligibilityRevision, pools: preview.pools.map(({ poolId, poolRevision }) => ({ poolId, poolRevision })), reason, confirm: true }, undefined, randomUUID(), user, bearer), { status: 409 }); assert.deepEqual(await snapshots(), before);
});
test('historical assignment recovery precedes stale pool checks and never reissues removed grants', async () => {
  const app = await createPool(); const assigned = await assign(await release([app.id])); const preview = await service.removalPreview(assigned.input.id, user, bearer);
  await service.change('removed', assigned.input.id, { userId: target.id, eligibilityRevision: target.eligibilityRevision, pools: preview.pools, reason, confirm: true }, `"company-blueprint-assignment-${assigned.input.id}-1"`, randomUUID(), user, bearer);
  const before = await snapshots(); assert.equal((await service.change('assigned', null, assigned.input, undefined, assigned.operation, user, bearer)).outcome, 'already_applied'); assert.deepEqual(await snapshots(), before);
});
test('configuration identity is composite across blueprints and conflicts roll back without writes', async () => {
  const configurationId = randomUUID(); await assign(await release([], 5, configurationId)); await assign(await release([], 5, configurationId)); assert.equal((await service.effective(target.id, user, bearer)).effectiveConfigurations[0].sources.length, 2);
  const blueprintId = await release([], 10); const before = await snapshots(); await assert.rejects(assign(blueprintId), { status: 409 }); assert.deepEqual(await snapshots(), before);
});
test('disabled and re-enabled users do not receive effective old-generation configurations', async () => {
  const assigned = await assign(await release()); target.enabled = false; target.eligibilityRevision = '2'; assert.deepEqual((await service.effective(target.id, user, bearer)).assignments, []);
  target.enabled = true; target.eligibilityRevision = '3'; assert.deepEqual((await service.effective(target.id, user, bearer)).assignments, []); assert.equal((await service.get(assigned.input.id, user, bearer)).assignment.status, 'active'); await assert.rejects(service.preview({ userId: target.id, blueprintId: await release(), version: 1 }, user, bearer), { status: 409 });
});
test('actual pre-026 Company receipts survive upgrade and full migration replay without JSON restamping', async () => {
  const name = 'company_assignment_upgrade_' + randomUUID().replaceAll('-', ''); await administration.query('CREATE SCHEMA ' + name);
  const url = new URL(process.env.LICENSE_TEST_DATABASE_URL); url.searchParams.set('options', '-c search_path=' + name + ',public -c timezone=UTC'); const legacyPool = new Pool({ connectionString: url.toString(), max: 4 });
  try {
    const files = fs.readdirSync(directory).filter(filename => filename.endsWith('.sql')).sort();
    for (const filename of files.filter(filename => Number(filename.slice(0, 3)) <= 25)) await legacyPool.query(fs.readFileSync(path.join(directory, filename), 'utf8'));
    const legacyDatabase = { query: (...args) => legacyPool.query(...args), getClient: () => legacyPool.connect() };
    const legacy = new CompanyLicenses(new LicenseAllocator(legacyDatabase), { authority: { read: async (_bearer, _user, userId = null) => structuredClone({ ...application, target: userId ? { ...target, id: userId } : null }) } });
    const app = await legacy.create({ name: 'Actual pre-upgrade app', vendor: 'Legacy vendor', description: '', totalSeats: 2, reason }, user, bearer);
    await legacy.assign(app.id, { userId: target.id, reason, confirm: true }, `"company-pool-${app.id}-1"`, user, bearer);
    const assignment = (await legacy.assignments(app.id, {}, user, bearer)).assignments[0]; await legacy.revoke(app.id, assignment.id, { userId: target.id, reason, confirm: true }, `"company-pool-${app.id}-2"`, user, bearer);
    await legacy.update(app.id, { name: 'Actual upgraded metadata', vendor: 'Legacy vendor', description: '', totalSeats: 3, reason, confirm: true }, `"company-pool-${app.id}-3"`, user, bearer);
    await legacy.assign(app.id, { userId: target.id, reason, confirm: true }, `"company-pool-${app.id}-4"`, user, bearer);
    const originalEvents = (await legacyPool.query('SELECT to_jsonb(event) AS value FROM license_company_events event ORDER BY after_revision')).rows;
    const originalCommands = (await legacyPool.query('SELECT id,source,command,before_state FROM license_company_commands ORDER BY created_at,id')).rows;
    for (const filename of files.filter(filename => Number(filename.slice(0, 3)) > 25)) await legacyPool.query(fs.readFileSync(path.join(directory, filename), 'utf8'));
    for (const phase of ['upgraded', 'replayed']) {
      assert.deepEqual((await legacyPool.query('SELECT to_jsonb(event) AS value FROM license_company_events event ORDER BY after_revision')).rows, originalEvents, phase);
      assert.deepEqual((await legacyPool.query('SELECT id,source,command,before_state FROM license_company_commands ORDER BY created_at,id')).rows, originalCommands, phase);
      assert.ok((await legacyPool.query('SELECT license_company_event_valid(event) AS valid FROM license_company_events event')).rows.every(row => row.valid));
      assert.ok((await legacyPool.query('SELECT protocol,parent_operation_id FROM license_company_commands')).rows.every(row => row.protocol === 1 && row.parent_operation_id === null));
      assert.equal((await legacy.get(app.id, user, bearer)).usedSeats, 1); assert.equal((await legacy.history(app.id, {}, user, bearer)).total, 5);
      if (phase === 'upgraded') for (const filename of files) await legacyPool.query(fs.readFileSync(path.join(directory, filename), 'utf8'));
    }
  } finally { await legacyPool.end(); await administration.query('DROP SCHEMA IF EXISTS ' + name + ' CASCADE'); }
});
test('deferred WHEN false and missing admission receivers fail closed before any user assignment', async () => {
  await pool.query('DROP TRIGGER company_blueprint_assignment_commit ON company_blueprint_assignment_operations');
  await pool.query('CREATE CONSTRAINT TRIGGER company_blueprint_assignment_commit AFTER INSERT ON company_blueprint_assignment_operations DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN(false) EXECUTE FUNCTION company_blueprint_assignment_commit()');
  await assert.rejects(service.capabilities(user, bearer), { status: 503 });
});
test('current effective app evidence rejects a missing original canonical outbox', async () => {
  const app = await createPool(); await assign(await release([app.id]));
  await pool.query('ALTER TABLE license_company_outbox DISABLE TRIGGER zz_license_company_guard'); await pool.query('DELETE FROM license_company_outbox WHERE id=(SELECT id FROM license_company_commands WHERE protocol=2 LIMIT 1)'); await pool.query('ALTER TABLE license_company_outbox ENABLE TRIGGER zz_license_company_guard');
  await assert.rejects(service.effective(target.id, user, bearer), { status: 503 });
});
test('captured positive generation cannot refresh itself after a real eligibility change', async () => {
  const blueprintId = await release(); const preview = await service.preview({ userId: target.id, blueprintId, version: 1 }, user, bearer); target.eligibilityRevision = '3'; const before = await snapshots();
  await assert.rejects(service.change('assigned', null, { id: randomUUID(), userId: target.id, blueprintId, version: 1, eligibilityRevision: preview.eligibilityRevision, pools: [], reason, confirm: true }, undefined, randomUUID(), user, bearer), { status: 412 }); assert.deepEqual(await snapshots(), before);
});
test('historical exact assignment receipt remains recoverable with current negative and later positive eligibility', async () => {
  const assigned = await assign(await release()); const before = await snapshots();
  target.enabled = false; target.eligibilityRevision = '2'; assert.equal((await service.change('assigned', null, assigned.input, undefined, assigned.operation, user, bearer)).outcome, 'already_applied');
  target.enabled = true; target.eligibilityRevision = '3'; assert.equal((await service.change('assigned', null, assigned.input, undefined, assigned.operation, user, bearer)).outcome, 'already_applied'); assert.deepEqual(await snapshots(), before);
});
