'use strict';

const { test, beforeEach, afterEach, after } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { Pool } = require('pg');
const { CompanyLicenses } = require('../CompanyLicenses');
const { CompanyOffboarding } = require('../CompanyOffboarding');
const { CompanyBlueprintAssignments } = require('../CompanyBlueprintAssignments');
const { CompanyBlueprints } = require('../../CompanyBlueprints');
const { LicenseAllocator } = require('../LicenseAllocator');
const { COMPANY_LICENSE_PERMISSIONS, poolEtag, offboardingEtag } = require('../../../../../../packages/company-license-contract');
const { COMPANY_BLUEPRINT_PERMISSIONS, etag } = require('../../../../../../packages/company-blueprint-contract');
const { COMPANY_BLUEPRINT_ASSIGNMENT_PERMISSIONS } = require('../../../../../../packages/company-blueprint-assignment-contract');

assert.ok(process.env.LICENSE_TEST_DATABASE_URL, 'Use disposable native PostgreSQL');
const administration = new Pool({ connectionString: process.env.LICENSE_TEST_DATABASE_URL, max: 1 });
const bearer = 'Bearer explicit.lifecycle.native'; const reason = 'Explicit native lifecycle and immutable source review';
let schema; let pool; let database; let state; let companies; let assignments; let blueprints; let offboarding;
beforeEach(async () => {
  schema = 'company_lifecycle_' + randomUUID().replaceAll('-', ''); await administration.query('CREATE SCHEMA ' + schema);
  const url = new URL(process.env.LICENSE_TEST_DATABASE_URL); url.searchParams.set('options', '-c search_path=' + schema + ',public -c timezone=UTC'); pool = new Pool({ connectionString: url.toString(), max: 12 });
  const directory = path.join(__dirname, '../../db/migrations');
  for (const filename of fs.readdirSync(directory).filter(filename => filename.endsWith('.sql')).sort()) {
    try { await pool.query(fs.readFileSync(path.join(directory, filename), 'utf8')); }
    catch (error) { error.message = filename + ': ' + error.message; delete error.internalQuery; throw error; }
  }
  const now = Math.floor(Date.now() / 1000); const actor = randomUUID(); const target = randomUUID();
  const user = { actor_type: 'user', token_use: 'access', iss: 'https://explicit.native.lifecycle', sub: 'fixture-owner', jti: randomUUID(), exp: now + 3600, auth_time: now,
    identity_authorization: { userId: actor, revision: '1', linkRevision: '1', rolesRevision: 'a'.repeat(64) }, amr: ['pwd', 'otp'], mfa_authorization: { schemaVersion: 1, userId: actor, revision: '1', authTime: now, methods: ['pwd', 'otp'] } };
  const base = { schemaVersion: 1, issuer: user.iss, subject: user.sub, tokenId: user.jti, expiresAt: user.exp, context: user.identity_authorization,
    tenant: { id: randomUUID(), version: '1', generation: '1' }, actorUserId: actor, validUntil: now + 300 };
  state = { user, target, base, enabled: true, deleted: false, eligibility: '11', userRevision: '17', hook: null, sourceHook: null, revoked: false, disables: 0, errors: [] };
  const targetView = () => ({ id: target, revision: state.deleted ? null : state.userRevision, eligibilityRevision: state.eligibility, enabled: state.enabled, deleted: state.deleted });
  const appAuthority = { read: async (authorization, _user, userId = null) => {
    assert.equal(authorization, bearer); if (state.sourceHook) await state.sourceHook(); if (state.revoked) throw Object.assign(new Error('Original source withdrawn'), { status: 401 });
    if (userId !== null && userId !== target) throw Object.assign(new Error('Foreign native recipient'), { status: 404 });
    return structuredClone({ ...base, permissions: [...COMPANY_LICENSE_PERMISSIONS], target: userId === null ? null : targetView() });
  } };
  const assignmentAuthority = { read: async (authorization, _user, userId = null) => {
    await appAuthority.read(authorization, _user, userId);
    return structuredClone({ ...base, companyBlueprintAssignmentsProtocol: 1, permissions: [...COMPANY_BLUEPRINT_ASSIGNMENT_PERMISSIONS], target: userId === null ? null : targetView() });
  } };
  database = { query: (...args) => pool.query(...args), getClient: async () => {
    const client = await pool.connect(); return { query: async (...args) => {
      if (state.hook) await state.hook(client, ...args);
      try { return await client.query(...args); } catch (error) { state.errors.push({ code: error.code, message: error.message, where: error.where }); throw error; }
    }, release: error => client.release(error) };
  } };
  const allocator = new LicenseAllocator(database);
  assignments = new CompanyBlueprintAssignments(database, { allocator, authority: assignmentAuthority, applicationAuthority: appAuthority });
  companies = new CompanyLicenses(allocator, { authority: appAuthority, assignmentAuthority, executor: assignments });
  blueprints = new CompanyBlueprints(database, { authority: { read: async () => structuredClone({ ...base, companyBlueprintProtocol: 1, permissions: [...COMPANY_BLUEPRINT_PERMISSIONS] }) }, applicationAuthority: appAuthority });
  const identity = { user: async () => ({ id: target, name: 'Explicit synthetic Identity bridge fixture', userRevision: state.userRevision, eligibilityRevision: state.eligibility, enabled: state.enabled }),
    disable: async job => {
      state.disables++; const previous = state.eligibility; const before = state.userRevision; const changed = state.enabled;
      state.enabled = false; if (changed) { state.eligibility = '104'; state.userRevision = '108'; }
      return { schemaVersion: 1, workflowId: job.id, tenantId: base.tenant.id, userId: target, actorUserId: actor, operationId: changed ? randomUUID() : null, action: changed ? 'disabled' : 'already_disabled',
        beforeRevision: before, afterRevision: state.userRevision, beforeEligibilityRevision: previous, afterEligibilityRevision: state.eligibility, createdAt: new Date().toISOString(), deliveryStatus: 'pending' };
    } };
  offboarding = new CompanyOffboarding(companies, { identity });
});
afterEach(async () => { await pool?.end(); await administration.query('DROP SCHEMA IF EXISTS ' + schema + ' CASCADE'); });
after(async () => administration.end());
async function app() { return companies.create({ name: 'Native local app', vendor: 'Native vendor', description: '', totalSeats: 2, reason }, state.user, bearer); }
async function release(pools = []) {
  const id = randomUUID(); const document = { name: 'Native static blueprint', description: '', platform: 'all', configurations: [{ id: randomUUID(), type: 'screen_lock', name: 'Screen lock', payloadJson: '{"minutes":5,"requirePassword":true}' }], appPoolIds: pools.map(value => value.id) };
  await blueprints.change('created', id, { id, draft: document, reason, confirm: true }, undefined, randomUUID(), state.user, bearer);
  await blueprints.change('published', id, { reason, confirm: true }, etag({ id, revision: '1' }), randomUUID(), state.user, bearer); return id;
}
async function bind(blueprintId, pools = []) {
  const current = await Promise.all(pools.map(value => companies.get(value.id, state.user, bearer)));
  const id = randomUUID();
  await assignments.change('assigned', id, { id, userId: state.target, blueprintId, version: 1, eligibilityRevision: state.eligibility,
    pools: current.map(value => ({ poolId: value.id, poolRevision: value.revision })), reason, confirm: true }, undefined, randomUUID(), state.user, bearer); return id;
}
async function manual(product) {
  const preview = await companies.v2.assignmentPreview(product.id, { userId: state.target }, state.user, bearer);
  const body = { userId: state.target, eligibilityRevision: state.eligibility, assignmentId: preview.assignment?.id || null, sources: preview.assignment?.sources || [], reason, confirm: true };
  return companies.v2.assign(product.id, body, poolEtag({ id: product.id, revision: preview.poolRevision }), randomUUID(), state.user, bearer);
}
async function workflow() {
  const input = { workflowId: randomUUID(), userId: state.target, userRevision: state.userRevision, eligibilityRevision: state.eligibility, reason, confirm: true };
  return { input, result: await offboarding.v2.create(input, input.workflowId, state.user, bearer) };
}
async function snapshot() {
  const result = {};
  for (const relation of ['license_catalog', 'license_subjects', 'license_assignments', 'license_assignment_sources', 'license_grants', 'license_grant_events', 'license_audit_events', 'license_company_commands', 'license_company_origins', 'license_company_events', 'license_company_outbox', 'company_blueprint_user_assignments', 'company_blueprint_assignment_operations', 'company_blueprint_assignment_events', 'company_blueprint_assignment_outbox']) {
    result[relation] = (await pool.query('SELECT to_jsonb(actual) AS value FROM ' + relation + ' actual ORDER BY to_jsonb(actual)::text')).rows;
  }
  return result;
}

test('027 compiles with the actual P2 kernel and all mandatory lifecycle receivers', async () => {
  await pool.query('SELECT company_blueprint_assignment_receiving()');
  assert.equal((await pool.query('SELECT count(*)::integer AS count FROM company_offboarding_v2_receiver_manifest')).rows[0].count, 12);
});
test('manual plus two independent blueprints produce three user grants and one actual seat', async () => {
  const product = await app(); await manual(product); await bind(await release([product]), [product]); await bind(await release([product]), [product]);
  const result = await companies.v2.assignments(product.id, {}, state.user, bearer);
  assert.equal(result.total, 1); assert.deepEqual(result.assignments[0].sources.map(value => value.sourceType), ['blueprint', 'blueprint', 'direct']);
  assert.equal((await companies.get(product.id, state.user, bearer)).usedSeats, 1);
  assert.deepEqual((await pool.query('SELECT DISTINCT kind,eligibility_revision FROM license_grants WHERE license_id=$1', [product.id])).rows, [{ kind: 'direct', eligibility_revision: '11' }]);
});
test('manual added after a blueprint retains the projection and manual-only revoke preserves blueprint grants', async () => {
  const product = await app(); await bind(await release([product]), [product]);
  const first = await companies.v2.assignmentPreview(product.id, { userId: state.target }, state.user, bearer); const added = await manual(product);
  assert.equal(added.seatAllocated, false); assert.equal(added.sourceAdded, true); assert.equal(added.assignmentId, first.assignment.id);
  const preview = await companies.v2.assignmentPreview(product.id, { userId: state.target }, state.user, bearer);
  const removed = await companies.v2.revoke(product.id, preview.assignment.id, { userId: state.target, eligibilityRevision: state.eligibility, sources: preview.assignment.sources, reason, confirm: true },
    poolEtag({ id: product.id, revision: preview.poolRevision }), randomUUID(), state.user, bearer);
  assert.equal(removed.sourceRemoved, true); assert.equal(removed.seatReleased, false); assert.equal(removed.effectiveAssignmentRetained, true);
  assert.equal((await companies.v2.assignments(product.id, {}, state.user, bearer)).assignments[0].sources[0].sourceType, 'blueprint');
});
test('complete negative workflow retires mixed sources and an independent zero-app binding', async () => {
  const product = await app(); await manual(product); await bind(await release([product]), [product]); await bind(await release());
  const { result } = await workflow(); assert.equal(result.result.workflow.phase, 'completed_local', JSON.stringify({ failure: result.result.workflow.failure, errors: state.errors })); assert.equal(result.result.workflow.totalBindings, 2); assert.equal(result.result.workflow.completedBindings, 2);
  assert.equal((await companies.get(product.id, state.user, bearer)).usedSeats, 0);
  assert.equal((await pool.query("SELECT count(*)::integer AS count FROM company_blueprint_user_assignments WHERE status='active'")).rows[0].count, 0);
  assert.equal((await pool.query('SELECT count(*)::integer AS count FROM license_assignment_sources')).rows[0].count, 0);
});
test('zero-app-only binding is captured and retired without inventing a pool child or seat', async () => {
  await bind(await release()); const { result } = await workflow();
  assert.equal(result.result.workflow.phase, 'completed_local', JSON.stringify({ failure: result.result.workflow.failure, errors: state.errors })); assert.equal(result.result.workflow.totalLicenses, 0); assert.equal(result.result.workflow.completedBindings, 1);
  assert.equal((await pool.query('SELECT count(*)::integer AS count FROM license_company_commands WHERE protocol=2')).rows[0].count, 0);
  const parent = (await pool.query("SELECT source,application_source FROM company_blueprint_assignment_operations WHERE action='retire_sources'")).rows[0];
  assert.equal(parent.application_source, null); assert.equal(parent.source.target.enabled, false);
});
test('V1 source-dependent requests require upgrade while pool metadata remains editable', async () => {
  const product = await app(); await bind(await release([product]), [product]);
  await assert.rejects(companies.assignments(product.id, {}, state.user, bearer), error => error.message === 'upgrade_required');
  await assert.rejects(companies.returnPreview(state.target, {}, state.user, bearer), error => error.message === 'upgrade_required');
  await assert.rejects(offboarding.preview(state.target, state.user, bearer), error => error.message === 'upgrade_required');
  const current = await companies.get(product.id, state.user, bearer);
  const edited = await companies.update(product.id, { name: current.name + ' edited', vendor: current.vendor, description: current.description, totalSeats: 3, reason, confirm: true }, poolEtag(current), state.user, bearer);
  assert.equal(edited.totalSeats, 3); assert.equal(edited.usedSeats, 1);
});
test('completed original negative workflow is historical after reactivation and cannot remove new source incarnations', async () => {
  const product = await app(); await bind(await release([product]), [product]); const { result } = await workflow();
  assert.equal(result.result.workflow.phase, 'completed_local'); state.enabled = true; state.eligibility = '217'; state.userRevision = '219';
  await manual(product); await bind(await release()); const before = await snapshot();
  const job = result.result.workflow;
  const recovered = await offboarding.v2.continue(job.id, { confirm: true, reason, userRevision: job.requestedRevision, assignments: [], bindings: [] }, offboardingEtag(job), randomUUID(), state.user, bearer);
  assert.equal(recovered.currentTarget.enabled, true); assert.deepEqual(recovered.workflow.checkpoint, job.checkpoint); assert.deepEqual(await snapshot(), before);
});

test('a manual acknowledgement recovers its immutable result before a newer pool ETag without creating another source', async () => {
  const product = await app(); const key = randomUUID(); const body = { userId: state.target, eligibilityRevision: state.eligibility, assignmentId: null, sources: [], reason, confirm: true };
  const first = await companies.v2.assign(product.id, body, poolEtag(product), key, state.user, bearer);
  await bind(await release([product]), [product]); const before = await snapshot();
  const recovered = await companies.v2.assign(product.id, body, poolEtag(product), key, state.user, bearer);
  assert.equal(recovered.outcome, 'already_applied'); assert.equal(recovered.assignmentId, first.assignmentId); assert.equal(recovered.poolRevision, first.poolRevision); assert.deepEqual(await snapshot(), before);
});
test('source retirement of more than 25 pools is one complete transaction and closes every spanning binding', async () => {
  const products = []; for (let index = 0; index < 26; index++) products.push(await app());
  await bind(await release(products.slice(0, 25)), products.slice(0, 25)); await bind(await release(products.slice(25)), products.slice(25)); await bind(await release());
  const { result } = await workflow(); assert.equal(result.result.workflow.phase, 'completed_local', JSON.stringify({ failure: result.result.workflow.failure, errors: state.errors })); assert.equal(result.result.workflow.totalLicenses, 26); assert.equal(result.result.workflow.completedBindings, 3);
  const parents = (await pool.query("SELECT id,transaction_id FROM company_blueprint_assignment_operations WHERE action='retire_sources'")).rows; assert.equal(parents.length, 1);
  const children = (await pool.query('SELECT DISTINCT transaction_id FROM license_company_commands WHERE parent_operation_id=$1', [parents[0].id])).rows;
  assert.deepEqual(children, [{ transaction_id: parents[0].transaction_id }]); assert.equal((await pool.query('SELECT count(*)::integer AS count FROM license_assignment_sources')).rows[0].count, 0);
});
test('failure in the last captured retirement pool rolls back every earlier source, seat and binding effect', async () => {
  const products = [await app(), await app()]; await bind(await release(products), products); await bind(await release());
  const last = products.map(value => value.id).sort().at(-1); const before = await snapshot();
  await pool.query(`CREATE FUNCTION native_retirement_reject() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF OLD.license_id='${last}'::uuid THEN RAISE EXCEPTION 'Explicit native last-child failure';END IF;RETURN OLD;END;$$;CREATE TRIGGER native_retirement_reject BEFORE DELETE ON license_assignment_sources FOR EACH ROW EXECUTE FUNCTION native_retirement_reject()`);
  const { result } = await workflow(); assert.equal(result.result.workflow.phase, 'paused'); assert.equal(result.result.workflow.failure.step, 'licenses'); assert.deepEqual(await snapshot(), before);
  await pool.query('DROP TRIGGER native_retirement_reject ON license_assignment_sources');
  const job = result.result.workflow;
  const completed = await offboarding.v2.continue(job.id, { confirm: true, reason, userRevision: job.requestedRevision,
    assignments: job.reviewAssignments.map(value => ({ poolId: value.poolId, poolRevision: value.poolRevision, assignmentId: value.id, sources: value.sources })), bindings: job.nextBindings.map(value => ({ id: value.id, revision: value.revision })) }, offboardingEtag(job), randomUUID(), state.user, bearer);
  assert.equal(completed.workflow.phase, 'completed_local');
});
test('a negative source changed after actual source deletion cannot retain any pool or binding effects', async () => {
  const product = await app(); await bind(await release([product]), [product]); const before = await snapshot(); let changed = false;
  state.hook = async (_client, sql) => { if (!changed && sql.startsWith('DELETE FROM license_assignment_sources')) { changed = true; state.enabled = true; state.eligibility = '217'; state.userRevision = '219'; } };
  const { result } = await workflow(); assert.equal(changed, true); assert.equal(result.result.workflow.phase, 'paused'); assert.deepEqual(await snapshot(), before);
  assert.equal(result.result.workflow.checkpoint.afterEligibilityRevision, '104');
});
test('an empty source-and-binding workflow produces only actual negative journal evidence', async () => {
  const { result } = await workflow(); assert.equal(result.result.workflow.phase, 'completed_local', JSON.stringify({ failure: result.result.workflow.failure, errors: state.errors })); assert.equal(result.result.workflow.totalLicenses, 0); assert.equal(result.result.workflow.totalBindings, 0);
  assert.equal((await pool.query('SELECT count(*)::integer AS count FROM company_blueprint_assignment_operations')).rows[0].count, 0);
});
test('a missing mandatory lifecycle outbox receiver cannot acknowledge or retain a new workflow', async () => {
  await pool.query('ALTER TABLE company_offboarding_v2_outbox DISABLE TRIGGER company_offboarding_v2_outbox_guard');
  await assert.rejects(workflow()); assert.equal((await pool.query('SELECT count(*)::integer AS count FROM company_offboarding_v2_jobs')).rows[0].count, 0);
});
test('standalone manual-only negative cleanup does not close an unseen zero-app binding', async () => {
  const product = await app(); await manual(product); await bind(await release()); state.enabled = false; state.eligibility = '104';
  const preview = await companies.v2.returnPreview(state.target, {}, state.user, bearer); assert.equal(preview.workflowRequired, true); const before = await snapshot();
  await assert.rejects(companies.v2.returnLicenses(state.target, { workflowId: null, eligibilityRevision: state.eligibility,
    assignments: preview.assignments.map(value => ({ poolId: value.poolId, poolRevision: value.poolRevision, assignmentId: value.id, sources: value.sources })), bindings: [], reason, confirm: true }, randomUUID(), state.user, bearer));
  assert.deepEqual(await snapshot(), before);
});
