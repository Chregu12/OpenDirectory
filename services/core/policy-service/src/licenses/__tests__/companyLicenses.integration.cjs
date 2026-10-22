'use strict';

const { test, beforeEach, afterEach, after } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { Pool } = require('pg');
const { LicenseAllocator } = require('../LicenseAllocator');
const { CompanyLicenses } = require('../CompanyLicenses');
const { CompanyLicenseAuthority } = require('../CompanyLicenseAuthority');
const { CompanyOffboarding } = require('../CompanyOffboarding');
const { companyLicenseContext } = require('../CompanyLicenseContext');
const { COMPANY_LICENSE_PERMISSIONS, poolEtag, offboardingEtag } = require('../../../../../../packages/company-license-contract');

assert.ok(process.env.LICENSE_TEST_DATABASE_URL, 'Run scripts/test-company-licenses.js against disposable native PostgreSQL');
const administration = new Pool({ connectionString: process.env.LICENSE_TEST_DATABASE_URL, max: 1 });
const migrations = path.join(__dirname, '../../db/migrations');
const bearer = 'Bearer explicit.company.native.fixture';
let schema;
let pool;
let database;
let allocator;
let companies;
let fixture;
let roles;

function serverFixture() {
  const authTime = Math.floor(Date.now() / 1000);
  const actorUserId = randomUUID();
  const tenant = { id: randomUUID(), version: '1', generation: '1' };
  const user = { actor_type: 'user', iss: 'https://company.native.fixture', sub: 'explicit-native-company-owner', jti: randomUUID(), exp: authTime + 3600, auth_time: authTime,
    identity_authorization: { userId: actorUserId, revision: '1', linkRevision: '1', rolesRevision: 'a'.repeat(64) } };
  const source = { schemaVersion: 1, issuer: user.iss, subject: user.sub, tokenId: user.jti, expiresAt: user.exp, context: structuredClone(user.identity_authorization),
    tenant, actorUserId, permissions: [...COMPANY_LICENSE_PERMISSIONS], validUntil: authTime + 300, target: null };
  const ownUser = randomUUID();
  const targets = new Map([[ownUser, { id: ownUser, revision: '1', eligibilityRevision: '1', enabled: true, deleted: false }]]);
  const state = { source, user, ownUser, targets, calls: [], revoked: false, beforeQuery: null };
  state.authority = new CompanyLicenseAuthority({ endpoint: 'https://company.native.fixture/api/identity/company-licenses', fetchImpl: async (endpoint, request) => {
    assert.equal(endpoint.href, 'https://company.native.fixture/api/identity/company-licenses');
    assert.equal(request.headers.Authorization, bearer);
    assert.equal(request.redirect, 'error');
    assert.equal(request.cache, 'no-store');
    const targetId = request.method === 'POST' ? JSON.parse(request.body).userId : null;
    const status = state.revoked ? 401 : targetId !== null && !targets.has(targetId) ? 404 : 200;
    state.calls.push({ targetId, status });
    return new Response(JSON.stringify(status === 200 ? { ...source, target: targetId === null ? null : targets.get(targetId) } : { error: 'Explicit fixture rejected original source' }),
      { status, headers: { 'content-type': 'application/json' } });
  } });
  return state;
}

async function migrate(client = pool) {
  for (const name of fs.readdirSync(migrations).filter(name => name.endsWith('.sql')).sort()) await client.query(fs.readFileSync(path.join(migrations, name), 'utf8'));
}

function instrument(client) {
  return {
    async query(sql, parameters) {
      if (fixture.beforeQuery) await fixture.beforeQuery(client, sql, parameters);
      return client.query(sql, parameters);
    },
    release: () => client.release(),
  };
}

function create(seats = 2) {
  return companies.create({ name: 'Native Company App', vendor: 'Native Test Vendor', description: '', totalSeats: seats, reason: 'Explicitly reviewed local company pool' }, fixture.user, bearer);
}

function assign(product, userId = fixture.ownUser) {
  return companies.assign(product.id, { userId, confirm: true, reason: 'Explicit native direct allocation review' }, poolEtag(product), fixture.user, bearer);
}

function revoke(product, assignment, userId = fixture.ownUser) {
  return companies.revoke(product.id, assignment.id, { userId, confirm: true, reason: 'Explicit native direct release review' }, poolEtag(product), fixture.user, bearer);
}

function updateValues(product, changes = {}) {
  return { name: product.name, vendor: product.vendor, description: product.description, totalSeats: product.totalSeats, ...changes };
}

function update(product, changes = {}) {
  return companies.update(product.id, { ...updateValues(product, { name: product.name + ' Edited', ...changes }), confirm: true, reason: 'Explicit native metadata and finite stock review' }, poolEtag(product), fixture.user, bearer);
}

function command(action = 'create', product = null, changes = {}) {
  return { id: randomUUID(), correlationId: randomUUID(), licenseId: product?.id || randomUUID(), action, expectedVersion: product?.revision || '0', reason: 'Explicit original native SQL command',
    values: action === 'create' ? { name: 'Native SQL Pool', vendor: 'Native SQL Vendor', description: '', totalSeats: 2 } : action === 'update' ? updateValues(product, { name: product.name + ' SQL Edited' }) : null, assignmentId: null, ...changes };
}

function proof(action = 'create', userId = fixture.ownUser) {
  return structuredClone({ ...fixture.source, target: ['create', 'update'].includes(action) ? null : fixture.targets.get(userId) });
}

async function begin(client, source, request) {
  await client.query("SELECT set_config('opendirectory.license_actor_user',$1,true),set_config('opendirectory.license_actor_issuer',$2,true),set_config('opendirectory.license_actor_subject',$3,true)",
    [source.actorUserId, source.issuer, source.subject]);
  assert.equal((await client.query('SELECT license_company_begin($1::jsonb,$2::jsonb) AS command_id', [source, request])).rows[0].command_id, request.id);
}

async function transaction(operation) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN'); const result = await operation(client); await client.query('COMMIT'); return result;
  } catch (error) { await client.query('ROLLBACK'); throw error; } finally { client.release(); }
}

async function catalog(client, source, request) {
  await client.query("INSERT INTO license_catalog(id,name,vendor,description,total_seats,business_tenant_id,business_revision) VALUES($1,$2,$3,$4,$5,$6,1)",
    [request.licenseId, request.values.name, request.values.vendor, request.values.description, request.values.totalSeats, source.tenant.id]);
}

async function editCatalog(client, source, request) {
  const product = (await client.query('SELECT * FROM license_catalog WHERE id=$1', [request.licenseId])).rows[0];
  await client.query('UPDATE license_catalog SET name=$2,vendor=$3,description=$4,total_seats=$5,updated_at=clock_timestamp() WHERE id=$1',
    [request.licenseId, request.values.name, request.values.vendor, request.values.description, request.values.totalSeats]);
  await client.query('INSERT INTO license_audit_events(license_id,action,actor,details,actor_issuer,actor_subject) VALUES($1,$2,$3,$4,$5,$6)',
    [request.licenseId, 'pool-updated', source.actorUserId, { before: { name: product.name, vendor: product.vendor, description: product.description, totalSeats: product.total_seats }, after: request.values, reason: request.reason }, source.issuer, source.subject]);
}

async function snapshot() {
  const result = {};
  for (const relation of ['license_catalog', 'license_subjects', 'license_assignments', 'license_assignment_sources', 'license_grants', 'license_grant_events', 'license_audit_events',
    'license_company_commands', 'license_company_origins', 'license_company_events', 'license_company_outbox']) {
    result[relation] = (await pool.query('SELECT to_jsonb(actual) AS state FROM ' + relation + ' actual ORDER BY to_jsonb(actual)::text')).rows;
  }
  return result;
}

beforeEach(async () => {
  schema = 'company_license_' + randomUUID().replaceAll('-', ''); roles = [];
  await administration.query('CREATE SCHEMA ' + schema);
  const url = new URL(process.env.LICENSE_TEST_DATABASE_URL);
  url.searchParams.set('options', '-c search_path=' + schema + ',public -c timezone=UTC');
  pool = new Pool({ connectionString: url.toString(), max: 12 });
  await migrate();
  fixture = serverFixture();
  database = { query: (...parameters) => pool.query(...parameters), getClient: async () => instrument(await pool.connect()) };
  allocator = new LicenseAllocator(database);
  companies = new CompanyLicenses(allocator, { authority: fixture.authority });
});
afterEach(async () => {
  await pool?.end(); await administration.query('DROP SCHEMA IF EXISTS ' + schema + ' CASCADE');
  for (const role of roles) { await administration.query('DROP OWNED BY ' + role); await administration.query('DROP ROLE ' + role); }
});
after(async () => administration.end());

async function returnFixture(count = 2) {
  for (let index = 0; index < count; index += 1) await assign(await create(2));
  fixture.targets.set(fixture.ownUser, { id: fixture.ownUser, revision: '2', eligibilityRevision: '2', enabled: false, deleted: false });
  const preview = await companies.returnPreview(fixture.ownUser, {}, fixture.user, bearer);
  const input = { reason: 'Confirmed native inactive employee local license return', confirm: true,
    assignments: preview.assignments.map(item => ({ poolId: item.poolId, assignmentId: item.id, poolRevision: item.poolRevision })) };
  return { preview, input };
}

async function workflowFixture(count = 2) {
  for (let index = 0; index < count; index += 1) await assign(await create(2));
  const intent = { workflowId: randomUUID(), userId: fixture.ownUser, userRevision: '41', eligibilityRevision: fixture.targets.get(fixture.ownUser).eligibilityRevision, reason: 'Explicit native combined account and local license offboarding', confirm: true };
  const identity = {
    calls: 0, gate: null,
    async user() { const target = fixture.targets.get(fixture.ownUser); return { id: fixture.ownUser, name: 'Explicit native Identity fixture', userRevision: '41', eligibilityRevision: target.eligibilityRevision, enabled: target.enabled }; },
    async disable(job) {
      this.calls += 1; if (this.gate) await this.gate();
      const before = fixture.targets.get(fixture.ownUser); const changed = before.enabled;
      const after = { ...before, enabled: false, revision: changed ? '2' : before.revision, eligibilityRevision: changed ? '9007199254740993' : before.eligibilityRevision };
      fixture.targets.set(fixture.ownUser, after);
      return { schemaVersion: 1, workflowId: job.id, tenantId: fixture.source.tenant.id, userId: fixture.ownUser, actorUserId: fixture.source.actorUserId,
        operationId: changed ? randomUUID() : null, action: changed ? 'disabled' : 'already_disabled', beforeRevision: '41', afterRevision: changed ? '42' : '41',
        beforeEligibilityRevision: before.eligibilityRevision, afterEligibilityRevision: after.eligibilityRevision, createdAt: new Date().toISOString(), deliveryStatus: 'pending' };
    },
  };
  return { intent, identity, workflow: new CompanyOffboarding(companies, { identity }) };
}

test('durable combined workflow uses actual local allocator receipts and a distinctly explicit synthetic Identity bridge fixture', async () => {
  const { intent, identity, workflow } = await workflowFixture();
  const result = await workflow.create(intent, fixture.user, bearer);
  assert.equal(result.created, true); assert.equal(result.result.workflow.phase, 'completed_local'); assert.equal(result.result.workflow.completedLicenses, 2);
  assert.equal(result.result.currentTarget.eligibilityRevision, '9007199254740993'); assert.equal(identity.calls, 1);
  assert.equal((await companies.returnPreview(fixture.ownUser, {}, fixture.user, bearer)).total, 0);
  const history = await workflow.history(intent.workflowId, {}, fixture.user, bearer);
  assert.ok(history.events.length >= 5); assert.ok(history.events.every(event => event.deliveryStatus === 'pending'));
  const releases = (await pool.query("SELECT * FROM license_company_events WHERE type='app.license.released' AND correlation_id=$1", [intent.workflowId])).rows;
  assert.equal(releases.length, 2);
  const recovered = await new CompanyOffboarding(companies, { identity }).create(intent, fixture.user, bearer);
  assert.equal(recovered.created, false); assert.equal(recovered.result.workflow.revision, result.result.workflow.revision); assert.equal(identity.calls, 1);
  assert.equal((await workflow.history(intent.workflowId, {}, fixture.user, bearer)).total, history.total);
});

test('a restarted workflow reconstructs one committed release whose journal acknowledgement was lost without executing that grant again', async () => {
  const { intent, identity, workflow } = await workflowFixture(); const save = workflow.journal.save.bind(workflow.journal); let withheld = false;
  workflow.journal.save = async (...parameters) => {
    if (!withheld && parameters[3].items?.some(item => item.status === 'released')) { withheld = true; throw Object.assign(new Error('Explicit native journal acknowledgement outage'), { status: 503 }); }
    return save(...parameters);
  };
  const partial = (await workflow.create(intent, fixture.user, bearer)).result;
  assert.equal(partial.workflow.phase, 'paused'); assert.equal(partial.workflow.completedLicenses, 0);
  assert.equal((await companies.returnPreview(fixture.ownUser, {}, fixture.user, bearer)).total, 1);
  const restarted = new CompanyOffboarding(companies, { identity });
  const result = await restarted.continue(intent.workflowId, { confirm: true, reason: intent.reason, userRevision: partial.workflow.requestedRevision,
    assignments: partial.workflow.reviewAssignments.map(item => ({ poolId: item.poolId, assignmentId: item.assignmentId, poolRevision: item.poolRevision })) }, offboardingEtag(partial.workflow), fixture.user, bearer);
  assert.equal(result.workflow.phase, 'completed_local'); assert.equal(result.workflow.completedLicenses, 2); assert.equal(identity.calls, 1);
  assert.equal((await pool.query("SELECT count(*)::integer AS count FROM license_company_events WHERE type='app.license.released' AND correlation_id=$1", [intent.workflowId])).rows[0].count, 2);
});

test('already-disabled zero-license offboarding finishes only its local scope without inventing an Identity mutation', async () => {
  const { intent, identity, workflow } = await workflowFixture(0); fixture.targets.get(fixture.ownUser).enabled = false;
  const result = (await workflow.create(intent, fixture.user, bearer)).result;
  assert.equal(result.workflow.phase, 'completed_local'); assert.equal(result.workflow.totalLicenses, 0); assert.equal(result.workflow.checkpoint.action, 'already_disabled');
  assert.equal(result.workflow.checkpoint.operationId, null); assert.equal(identity.calls, 1);
  assert.equal((await pool.query('SELECT count(*)::integer AS count FROM license_company_commands')).rows[0].count, 0);
});

test('a later active lifecycle cannot be disabled by an older durable intent even before its first account checkpoint', async () => {
  const { intent, identity, workflow } = await workflowFixture(1);
  const source = await fixture.authority.read(bearer, fixture.user, fixture.ownUser);
  const lock = await workflow.journal.lock(source.tenant.id, intent.workflowId);
  try { await workflow.journal.create(lock.client, source, intent, () => companies.unchanged(source, fixture.user, bearer)); } finally { await lock.release(); }
  const before = await workflow.get(intent.workflowId, fixture.user, bearer); fixture.targets.get(fixture.ownUser).eligibilityRevision = '700';
  const result = await workflow.continue(intent.workflowId, { confirm: true, reason: intent.reason, userRevision: '41', assignments: [] }, offboardingEtag(before.workflow), fixture.user, bearer);
  assert.equal(result.workflow.phase, 'paused'); assert.deepEqual(result.workflow.failure, { code: 409, step: 'verify' }); assert.equal(identity.calls, 0);
  assert.equal((await pool.query('SELECT count(*)::integer AS count FROM license_assignments')).rows[0].count, 1);
});

test('the durable workflow session lock rejects concurrent execution rather than overlapping account commands', async () => {
  const { intent, identity, workflow } = await workflowFixture(0); let entered; let release;
  const started = new Promise(resolve => { entered = resolve; }); const gate = new Promise(resolve => { release = resolve; });
  identity.gate = async () => { entered(); await gate; };
  const first = workflow.create(intent, fixture.user, bearer);
  try { await started; await assert.rejects(new CompanyOffboarding(companies, { identity }).create(intent, fixture.user, bearer), error => error.status === 409); }
  finally { release(); }
  assert.equal((await first).result.workflow.phase, 'completed_local'); assert.equal(identity.calls, 1);
});

test('own employee return preview is a complete source-bound read snapshot, never an implicit account disable or allocation change', async () => {
  await assign(await create()); const before = await snapshot();
  const preview = await companies.returnPreview(fixture.ownUser, {}, fixture.user, bearer);
  assert.equal(preview.actorUserId, fixture.source.actorUserId); assert.equal(preview.tenantId, fixture.source.tenant.id);
  assert.deepEqual(preview.target, { enabled: true, deleted: false, eligibilityRevision: '1' });
  assert.equal(preview.total, 1); assert.equal(preview.assignments.length, 1); assert.equal(preview.assignments[0].poolRevision, '2');
  assert.equal(preview.assignments[0].grantId, (await pool.query('SELECT grant_id FROM license_assignment_sources')).rows[0].grant_id);
  assert.deepEqual(await snapshot(), before);
});

test('preflight catalog rows and volatile retained receipt checks share one real read-only repeatable snapshot', async () => {
  let snapshots = 0;
  fixture.beforeQuery = async (client, sql) => {
    if (sql.startsWith('SELECT catalog.*') && !companyLicenseContext.getStore()) {
      assert.equal((await client.query('SHOW transaction_isolation')).rows[0].transaction_isolation, 'repeatable read');
      assert.equal((await client.query('SHOW transaction_read_only')).rows[0].transaction_read_only, 'on'); snapshots += 1;
    }
  };
  const { input } = await returnFixture(1);
  await companies.returnLicenses(fixture.ownUser, input, fixture.user, bearer);
  assert.ok(snapshots >= 4);
});

test('confirmed inactive employee return uses actual allocator transactions, one shared correlation and retained pending receipts', async () => {
  const { input } = await returnFixture(); const correlationId = randomUUID();
  const result = await companies.returnLicenses(fixture.ownUser, input, fixture.user, bearer, correlationId);
  assert.deepEqual(result.results.map(item => [item.status, item.code]), [['released', 200], ['released', 200]]);
  assert.equal(result.correlationId, correlationId);
  for (const relation of ['license_assignments', 'license_assignment_sources', 'license_fulfillment_targets']) assert.equal((await pool.query('SELECT count(*)::integer AS count FROM ' + relation)).rows[0].count, 0);
  const events = (await pool.query("SELECT event.*,outbox.status FROM license_company_events event JOIN license_company_outbox outbox USING(id) WHERE event.type='app.license.released' ORDER BY event.license_id")).rows;
  assert.equal(events.length, 2); assert.ok(events.every(event => event.correlation_id === correlationId && event.actor_user_id === fixture.source.actorUserId && event.target_user_id === fixture.ownUser && event.status === 'pending' && event.proof.source.target.enabled === false));
  assert.ok((await pool.query('SELECT license_company_pool_valid(id) AS valid,business_revision FROM license_catalog')).rows.every(row => row.valid && row.business_revision === '3'));
  assert.ok((await pool.query('SELECT DISTINCT ON(grant_id) state FROM license_grant_events ORDER BY grant_id,version DESC')).rows.every(row => row.state === 'revoked'));
  assert.equal((await companies.returnPreview(fixture.ownUser, {}, fixture.user, bearer)).total, 0);
});

test('an enabled employee and a foreign UUID cannot cause return side effects or an implicit account mutation', async () => {
  const { input } = await returnFixture(); fixture.targets.get(fixture.ownUser).enabled = true;
  const before = await snapshot();
  await assert.rejects(companies.returnLicenses(fixture.ownUser, input, fixture.user, bearer), error => error.status === 403);
  await assert.rejects(companies.returnPreview(randomUUID(), {}, fixture.user, bearer), error => error.status === 404);
  assert.deepEqual(await snapshot(), before);
});

test('all manifest preflight finishes before recipient lookup, so a stale later pool cannot partially return an earlier one', async () => {
  const { input } = await returnFixture(); input.assignments[1].poolRevision = '1'; fixture.calls.length = 0;
  const before = await snapshot();
  await assert.rejects(companies.returnLicenses(fixture.ownUser, input, fixture.user, bearer), error => error.status === 412);
  assert.equal(fixture.calls.length, 1); assert.equal(fixture.calls[0].targetId, null);
  assert.deepEqual(await snapshot(), before);
});

test('a real foreign company pool later in the manifest cannot probe its recipient or partially return an own earlier pool', async () => {
  const { input } = await returnFixture(1); const other = serverFixture();
  const foreign = new CompanyLicenses(allocator, { authority: other.authority });
  const product = await foreign.create({ name: 'Other actual tenant pool', vendor: 'Native vendor', description: '', totalSeats: 2, reason: 'Explicit independent own company stock' }, other.user, bearer);
  input.assignments.push({ poolId: product.id, assignmentId: randomUUID(), poolRevision: product.revision });
  fixture.calls.length = 0; const before = await snapshot();
  await assert.rejects(companies.returnLicenses(fixture.ownUser, input, fixture.user, bearer), error => error.status === 404);
  assert.deepEqual(fixture.calls, [{ targetId: null, status: 200 }]); assert.deepEqual(await snapshot(), before);
});

test('an old manifest cannot release a later regrant to the same employee after explicit reactivation', async () => {
  const { input } = await returnFixture(1); const oldId = input.assignments[0].assignmentId;
  await companies.returnLicenses(fixture.ownUser, input, fixture.user, bearer);
  fixture.targets.set(fixture.ownUser, { id: fixture.ownUser, revision: '3', eligibilityRevision: '3', enabled: true, deleted: false });
  await assign(await companies.get(input.assignments[0].poolId, fixture.user, bearer));
  fixture.targets.set(fixture.ownUser, { id: fixture.ownUser, revision: '4', eligibilityRevision: '4', enabled: false, deleted: false });
  const current = await companies.returnPreview(fixture.ownUser, {}, fixture.user, bearer);
  assert.notEqual(current.assignments[0].id, oldId); input.assignments[0].poolRevision = current.assignments[0].poolRevision;
  const before = await snapshot();
  await assert.rejects(companies.returnLicenses(fixture.ownUser, input, fixture.user, bearer), error => error.status === 404);
  assert.deepEqual(await snapshot(), before);
});

test('a real concurrent second-pool change retains the first return and stops later operations with an uncertain result', async () => {
  const { input } = await returnFixture(3); const otherUser = randomUUID();
  fixture.targets.set(otherUser, { id: otherUser, revision: '1', eligibilityRevision: '1', enabled: true, deleted: false });
  const original = companies.revoke.bind(companies); let calls = 0;
  companies.revoke = async (...parameters) => {
    calls += 1; const result = await original(...parameters);
    if (calls === 1) await assign(await companies.get(input.assignments[1].poolId, fixture.user, bearer), otherUser);
    return result;
  };
  const result = await companies.returnLicenses(fixture.ownUser, input, fixture.user, bearer);
  assert.deepEqual(result.results.map(item => [item.status, item.code]), [['released', 200], ['unconfirmed', 412], ['not_attempted', null]]);
  assert.equal(calls, 2);
  assert.equal((await companies.returnPreview(fixture.ownUser, {}, fixture.user, bearer)).total, 2);
  assert.equal((await pool.query("SELECT count(*)::integer AS count FROM license_company_events WHERE type='app.license.released'")).rows[0].count, 1);
});

test('a lost completion after an actual allocator commit remains unconfirmed and readback proves the committed release', async () => {
  const { input } = await returnFixture(1); const original = companies.revoke.bind(companies);
  companies.revoke = async (...parameters) => { await original(...parameters); throw Object.assign(new Error('Explicitly injected lost completion after commit'), { status: 503 }); };
  const result = await companies.returnLicenses(fixture.ownUser, input, fixture.user, bearer);
  assert.deepEqual(result.results.map(item => [item.status, item.code]), [['unconfirmed', 503]]);
  assert.equal((await companies.returnPreview(fixture.ownUser, {}, fixture.user, bearer)).total, 0);
  assert.equal((await pool.query("SELECT count(*)::integer AS count FROM license_company_events WHERE type='app.license.released'")).rows[0].count, 1);
  assert.ok((await pool.query('SELECT license_company_pool_valid(id) AS valid FROM license_catalog')).rows.every(row => row.valid));
});

test('a physically suppressed pending receipt prevents any confirmed return and leaves later assignments unattempted', async () => {
  const { input } = await returnFixture(); const before = await snapshot();
  await pool.query("CREATE FUNCTION suppress_return_receipt() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$; CREATE TRIGGER suppress_return_receipt BEFORE INSERT ON license_company_outbox FOR EACH ROW EXECUTE FUNCTION suppress_return_receipt()");
  const result = await companies.returnLicenses(fixture.ownUser, input, fixture.user, bearer);
  assert.deepEqual(result.results.map(item => [item.status, item.code]), [['unconfirmed', 503], ['not_attempted', null]]);
  assert.deepEqual(await snapshot(), before);
});

test('an original employee reactivation during real release SQL rolls back that transaction and withholds a batch receipt', async () => {
  const { input } = await returnFixture(1); const before = await snapshot();
  fixture.beforeQuery = async (_client, sql) => {
    if (sql.startsWith('INSERT INTO license_audit_events') && sql.includes('actor_issuer')) fixture.targets.get(fixture.ownUser).enabled = true;
  };
  await assert.rejects(companies.returnLicenses(fixture.ownUser, input, fixture.user, bearer), error => error.status === 401);
  assert.deepEqual(await snapshot(), before);
});

test('a retained deleted own employee can return actual local grants without reviving a profile or global subject', async () => {
  const { input } = await returnFixture(1);
  fixture.targets.set(fixture.ownUser, { id: fixture.ownUser, revision: null, eligibilityRevision: '3', enabled: false, deleted: true });
  const result = await companies.returnLicenses(fixture.ownUser, input, fixture.user, bearer);
  assert.equal(result.results[0].status, 'released');
  assert.equal((await pool.query('SELECT count(*)::integer AS count FROM license_assignments')).rows[0].count, 0);
  assert.equal((await pool.query('SELECT directory_deleted FROM license_subjects WHERE user_id=$1', [fixture.ownUser])).rows[0].directory_deleted, false);
  assert.equal((await pool.query("SELECT proof->'source'->'target' AS target FROM license_company_events WHERE type='app.license.released'")).rows[0].target.deleted, true);
});

test('employee return pages count all own actual assignments while exposing only the explicitly captured page', async () => {
  await returnFixture(3);
  const first = await companies.returnPreview(fixture.ownUser, { limit: '2' }, fixture.user, bearer);
  const second = await companies.returnPreview(fixture.ownUser, { limit: '2', page: '2' }, fixture.user, bearer);
  assert.equal(first.total, 3); assert.equal(first.assignments.length, 2); assert.equal(second.total, 3); assert.equal(second.assignments.length, 1);
  assert.equal(new Set([...first.assignments, ...second.assignments].map(item => item.id)).size, 3);
});

test('the actual 25-item maximum returns only the captured first page and preserves an unseen twenty-sixth grant', async () => {
  const { preview, input } = await returnFixture(26);
  assert.equal(preview.total, 26); assert.equal(preview.assignments.length, 25); assert.equal(input.assignments.length, 25);
  const unseen = (await companies.returnPreview(fixture.ownUser, { page: '2' }, fixture.user, bearer)).assignments[0];
  const result = await companies.returnLicenses(fixture.ownUser, input, fixture.user, bearer);
  assert.equal(result.results.length, 25); assert.ok(result.results.every(item => item.status === 'released'));
  const remaining = await companies.returnPreview(fixture.ownUser, {}, fixture.user, bearer);
  assert.equal(remaining.total, 1); assert.deepEqual(remaining.assignments[0], unseen);
  assert.equal((await pool.query("SELECT count(*)::integer AS count FROM license_company_events WHERE type='app.license.released'")).rows[0].count, 25);
  assert.ok((await pool.query('SELECT license_company_pool_valid(id) AS valid FROM license_catalog')).rows.every(row => row.valid));
});

test('all actual migrations install the four interfaces and keep canonical business columns nullable without legacy defaults', async () => {
  await pool.query('SELECT license_company_receiving()');
  const columns = (await pool.query("SELECT table_name,column_name,is_nullable,column_default FROM information_schema.columns WHERE table_schema=$1 AND column_name IN('business_tenant_id','business_revision') ORDER BY table_name,column_name", [schema])).rows;
  assert.equal(columns.length, 3);
  assert.ok(columns.every(column => column.is_nullable === 'YES' && column.column_default === null));
  const legacy = (await pool.query("INSERT INTO license_catalog(name,total_seats) VALUES('Unchanged global pool',0) RETURNING *")).rows[0];
  assert.equal(legacy.business_tenant_id, null); assert.equal(legacy.business_revision, null);
  assert.equal((await pool.query('SELECT license_company_pool_valid($1) AS valid', [legacy.id])).rows[0].valid, false);
});

test('the actual existing allocator assigns and releases one own seat with retained lineage, exact revisions, original proofs and pending-only receipts', async () => {
  const created = await create(1);
  assert.equal(created.revision, '1'); assert.equal(created.usedSeats, 0);
  assert.equal((await pool.query('SELECT count(*)::integer AS count FROM license_subjects')).rows[0].count, 0);
  const assigned = await assign(created);
  assert.equal(assigned.revision, '2'); assert.equal(assigned.usedSeats, 1); assert.equal(assigned.availableSeats, 0);
  const allocation = (await companies.assignments(created.id, {}, fixture.user, bearer)).assignments[0];
  const released = await revoke(assigned, allocation);
  assert.equal(released.revision, '3'); assert.equal(released.usedSeats, 0);
  const history = await companies.history(created.id, {}, fixture.user, bearer);
  assert.equal(history.events.length, 3);
  assert.deepEqual(history.events.map(event => event.type).sort(), ['app.license.assigned', 'app.license.pool.created', 'app.license.released']);
  assert.ok(history.events.every(event => event.deliveryStatus === 'pending'));
  const events = (await pool.query('SELECT * FROM license_company_events ORDER BY after_revision')).rows;
  assert.deepEqual(events.map(event => [event.before_revision, event.after_revision]), [[null, '1'], ['1', '2'], ['2', '3']]);
  assert.ok(events.every(event => event.id !== event.correlation_id && event.proof.source.tokenId === fixture.user.jti));
  assert.equal((await pool.query('SELECT state FROM license_grant_events ORDER BY version DESC LIMIT 1')).rows[0].state, 'revoked');
  assert.equal((await pool.query('SELECT license_company_pool_valid($1) AS valid', [created.id])).rows[0].valid, true);
  assert.equal((await pool.query('SELECT count(*)::integer AS count FROM license_fulfillment_targets')).rows[0].count, 0);
});

test('empty unconfigured company receivers preserve legacy truncate and actual global allocator behavior including unlimited pools', async () => {
  await pool.query('TRUNCATE license_catalog,license_subjects,license_company_commands CASCADE');
  const product = (await pool.query("INSERT INTO license_catalog(name,total_seats) VALUES('Actual legacy unlimited pool',0) RETURNING *")).rows[0];
  const legacy = new LicenseAllocator(database, { source: { user: async userId => ({ schemaVersion: 1, userId, revision: '1', enabled: true, deleted: false }) } });
  await legacy.assign(product.id, { assignee_type: 'user', assignee_id: randomUUID() }, randomUUID());
  assert.equal((await pool.query('SELECT used_seats FROM license_catalog WHERE id=$1', [product.id])).rows[0].used_seats, 1);
  assert.equal((await pool.query('SELECT count(*)::integer AS count FROM license_company_commands')).rows[0].count, 0);
});

test('all migrations replay an owned assigned pool through the exact old capacity no-op without restamping receipts or revisions', async () => {
  const product = await assign(await create());
  const before = await snapshot();
  await migrate();
  assert.deepEqual(await snapshot(), before);
  assert.equal((await companies.get(product.id, fixture.user, bearer)).revision, '2');
});

for (const earlier of [
  "INSERT INTO license_catalog(name,total_seats) VALUES('Earlier unrelated global write',2)",
  "INSERT INTO license_subjects(user_id) VALUES('earlier-unrelated-global-subject')",
  "UPDATE license_catalog SET name='Earlier unrelated global update'",
  'DELETE FROM license_catalog',
  'TRUNCATE license_subjects',
]) {
  test('an actual earlier legacy effect cannot ride a company admission: ' + earlier.split(' ').slice(0, 3).join(' '), async () => {
    await pool.query("INSERT INTO license_catalog(name,total_seats) VALUES('Earlier global seed',2)");
    const before = await snapshot();
    await assert.rejects(transaction(async client => {
      await client.query(earlier);
      await client.query("SELECT set_config('opendirectory.license_company','',true)");
      assert.equal((await client.query("SELECT count(*)::integer AS count FROM pg_locks WHERE locktype='advisory' AND pid=pg_backend_pid() AND classid=19770022::oid AND objid=1::oid AND mode='ShareLock'")).rows[0].count, 1);
      await begin(client, proof(), command());
    }), error => error.code === '42501');
    assert.deepEqual(await snapshot(), before);
  });
}

test('the shared SQL marker does not serialize or deny another backend clean company transaction', async () => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN'); await client.query("INSERT INTO license_catalog(name) VALUES('Concurrent legacy global pool')");
    const product = await create();
    assert.equal(product.revision, '1');
  } finally { await client.query('ROLLBACK'); client.release(); }
});

test('an unchanged original capacity replay before begin is a verified no-op rather than earlier unrelated write authority', async () => {
  const product = await create();
  await transaction(async client => {
    await client.query('UPDATE license_catalog SET used_seats=used_seats WHERE id=$1', [product.id]);
    const request = command();
    await begin(client, proof(), request); await catalog(client, proof(), request);
    assert.equal((await client.query('SELECT license_company_finish($1,$2::jsonb) AS id', [request.id, proof()])).rows[0].id, request.id);
  });
});

test('raw owned pool, subject, source and assignment mutations cannot use a global alias or forged GUC', async () => {
  const product = await assign(await create());
  const before = await snapshot();
  for (const [sql, parameters] of [
    ['UPDATE license_catalog SET total_seats=10 WHERE id=$1', [product.id]],
    ['DELETE FROM license_catalog WHERE id=$1', [product.id]],
    ['UPDATE license_subjects SET disabled=true WHERE user_id=$1', [fixture.ownUser]],
    ['UPDATE license_subjects SET business_tenant_id=NULL WHERE user_id=$1', [fixture.ownUser]],
    ['DELETE FROM license_subjects WHERE user_id=$1', [fixture.ownUser]],
    ['DELETE FROM license_assignment_sources WHERE license_id=$1', [product.id]],
    ['DELETE FROM license_assignments WHERE license_id=$1', [product.id]],
  ]) {
    await assert.rejects(transaction(async client => {
      await client.query("SELECT set_config('opendirectory.license_company',$1,true)", [randomUUID()]);
      await client.query(sql, parameters);
    }), error => ['42501', '23514'].includes(error.code));
  }
  assert.deepEqual(await snapshot(), before);
});

test('retained original admission rejects GUC-cleared unrelated writes after begin and prevents a second command in the same transaction', async () => {
  const before = await snapshot();
  for (const operation of [
    client => client.query("INSERT INTO license_catalog(name) VALUES('Unrelated after cleared admission')"),
    client => begin(client, proof(), command()),
    client => client.query('TRUNCATE license_requests'),
  ]) {
    await assert.rejects(transaction(async client => {
      await begin(client, proof(), command());
      await client.query("SELECT set_config('opendirectory.license_company','',true)");
      await operation(client);
    }), error => error.code === '42501');
  }
  assert.deepEqual(await snapshot(), before);
});

test('missing actual catalog effect or missing final receipt rolls back original admission and all effects', async () => {
  const before = await snapshot();
  await assert.rejects(transaction(async client => { const request = command(); await begin(client, proof(), request); await client.query('SELECT license_company_finish($1,$2)', [request.id, proof()]); }),
    error => error.code === '23514');
  await assert.rejects(transaction(async client => { const request = command(); await begin(client, proof(), request); await catalog(client, proof(), request); }),
    error => error.code === '23514');
  assert.deepEqual(await snapshot(), before);
});

for (const relation of ['license_catalog', 'license_company_origins', 'license_company_events', 'license_company_outbox']) {
  test('a physical no-effects receiver on ' + relation + ' cannot acknowledge a successful company creation', async () => {
    await pool.query("CREATE FUNCTION native_suppress_effect() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL;END;$$");
    await pool.query('CREATE TRIGGER aaa_native_suppress BEFORE INSERT ON ' + relation + ' FOR EACH ROW EXECUTE FUNCTION native_suppress_effect()');
    const before = await snapshot();
    await assert.rejects(create);
    assert.deepEqual(await snapshot(), before);
  });
}

for (const relation of ['license_assignment_sources', 'license_assignments', 'license_grants', 'license_grant_events', 'license_audit_events']) {
  test('suppressed actual allocator effect on ' + relation + ' rolls back subject bindings, allocation and revision', async () => {
    const product = await create();
    await pool.query("CREATE FUNCTION native_suppress_effect() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL;END;$$");
    await pool.query('CREATE TRIGGER aaa_native_suppress BEFORE INSERT ON ' + relation + ' FOR EACH ROW EXECUTE FUNCTION native_suppress_effect()');
    const before = await snapshot();
    await assert.rejects(assign(product));
    assert.deepEqual(await snapshot(), before);
  });
}

for (const [relation, trigger] of [
  ['license_catalog', 'zz_license_company_guard'],
  ['license_assignment_sources', 'zz_license_company_observe'],
  ['license_company_commands', 'license_company_commit'],
  ['license_company_outbox', 'license_company_truncate'],
  ['license_catalog', 'license_capacity_guard'],
  ['license_assignments', 'license_assignment_capacity_guard'],
]) {
  test('startup/read/write receiving checks fail closed for disabled ' + trigger, async () => {
    const product = await create();
    await pool.query('ALTER TABLE ' + relation + ' DISABLE TRIGGER ' + trigger);
    await assert.rejects(pool.query('SELECT license_company_receiving()'), error => error.code === '42501');
    await assert.rejects(companies.get(product.id, fixture.user, bearer), error => error.code === '42501');
    await assert.rejects(create(), error => error.code === '42501');
  });
}

test('truncation cannot erase any retained command, effect, lineage, audit or pending receipt', async () => {
  await assign(await create());
  const before = await snapshot();
  for (const relation of ['license_catalog', 'license_subjects', 'license_grants', 'license_grant_events', 'license_audit_events', 'license_company_commands', 'license_company_origins', 'license_company_events', 'license_company_outbox']) {
    await assert.rejects(pool.query('TRUNCATE ' + relation + ' CASCADE'), error => error.code === '42501');
  }
  assert.deepEqual(await snapshot(), before);
});

test('foreign original tenant, foreign bound subject and stale ETag reject before allocation effects', async () => {
  const product = await assign(await create());
  const before = await snapshot();
  await assert.rejects(transaction(client => begin(client, { ...proof('assign'), tenant: { ...fixture.source.tenant, id: randomUUID() } }, command('assign', product))), error => error.code === '42501');
  await assert.rejects(transaction(client => begin(client, proof('assign'), command('assign', product, { expectedVersion: '1' }))), error => error.code === '40001');
  assert.deepEqual(await snapshot(), before);
});

test('unused empty legacy target placeholder is bound once without resetting any prior field', async () => {
  await pool.query('INSERT INTO license_subjects(user_id) VALUES($1)', [fixture.ownUser]);
  const old = (await pool.query('SELECT * FROM license_subjects WHERE user_id=$1', [fixture.ownUser])).rows[0];
  await assign(await create());
  const current = (await pool.query('SELECT * FROM license_subjects WHERE user_id=$1', [fixture.ownUser])).rows[0];
  assert.equal(current.business_tenant_id, fixture.source.tenant.id); assert.equal(current.disabled, false); assert.deepEqual(current.updated_at, old.updated_at);
});

for (const history of ['disabled', 'directory', 'audit', 'retained-grant', 'request']) {
  test('legacy subject ' + history + ' needs controlled migration instead of silent ownership adoption or state reset', async () => {
    const identifier = fixture.ownUser;
    await pool.query('INSERT INTO license_subjects(user_id) VALUES($1)', [identifier]);
    if (history === 'disabled') await pool.query('UPDATE license_subjects SET disabled=true WHERE user_id=$1', [identifier]);
    if (history === 'directory') await pool.query('UPDATE license_subjects SET directory_revision=1,directory_enabled=true,directory_deleted=false WHERE user_id=$1', [identifier]);
    if (history === 'audit') await pool.query("INSERT INTO license_audit_events(action,actor,details) VALUES('retained-user-history','old-system',jsonb_build_object('userId',$1::text))", [identifier]);
    if (['retained-grant', 'request'].includes(history)) {
      const legacy = (await pool.query("INSERT INTO license_catalog(name,total_seats) VALUES('Earlier global participation',2) RETURNING id")).rows[0];
      if (history === 'request') await pool.query("INSERT INTO license_requests(license_id,requester_id) VALUES($1,$2)", [legacy.id, identifier]);
      else {
        await pool.query("INSERT INTO license_assignment_sources(license_id,user_id,source_type,source_id,assigned_by) VALUES($1,$2,'direct','direct','original-global-actor')", [legacy.id, identifier]);
        await pool.query('DELETE FROM license_assignment_sources WHERE license_id=$1', [legacy.id]);
      }
    }
    const product = await create(); const before = await snapshot();
    await assert.rejects(assign(product), error => error.code === '23514' || error.status === 409);
    assert.deepEqual(await snapshot(), before);
  });
}

test('deleted own target retains nullable record revision and can release a previously granted seat without global offboarding', async () => {
  const product = await assign(await create());
  const allocation = (await companies.assignments(product.id, {}, fixture.user, bearer)).assignments[0];
  fixture.targets.set(fixture.ownUser, { id: fixture.ownUser, revision: null, eligibilityRevision: '2', enabled: false, deleted: true });
  const released = await revoke(product, allocation);
  assert.equal(released.usedSeats, 0);
  const row = (await pool.query('SELECT proof FROM license_company_events WHERE type=$1', ['app.license.released'])).rows[0];
  assert.equal(row.proof.source.target.revision, null); assert.equal(row.proof.source.target.deleted, true);
});

test('malformed source and command fields, nonfinite seats and an inactive allocation target never create SQL admission', async () => {
  for (const change of [
    { command: { extra: true } }, { command: { expectedVersion: 0 } }, { command: { assignmentId: randomUUID() } },
    { command: { values: { name: 'X', vendor: 'Y', description: '', totalSeats: 0 } } },
    { command: { values: { name: 'X', vendor: 'Y', description: '', totalSeats: 10001 } } },
    { source: { permissions: ['company.apps.create'] } }, { source: { extra: true } },
    { source: { validUntil: Math.floor(Date.now() / 1000) - 1 } },
  ]) {
    await assert.rejects(transaction(client => begin(client, { ...proof(), ...change.source }, { ...command(), ...change.command })), error => error.code === '42501');
  }
  const product = await create();
  const source = proof('assign'); source.target.enabled = false;
  await assert.rejects(transaction(client => begin(client, source, command('assign', product))), error => error.code === '42501');
  assert.equal((await pool.query('SELECT count(*)::integer AS count FROM license_company_commands')).rows[0].count, 1);
});

test('an altered source checkpoint, duplicate finish or effects after finish cannot publish a receipt', async () => {
  const before = await snapshot();
  for (const mutation of ['source', 'duplicate', 'after']) {
    await assert.rejects(transaction(async client => {
      const request = command(); await begin(client, proof(), request); await catalog(client, proof(), request);
      await client.query('SELECT license_company_finish($1,$2)', [request.id, mutation === 'source' ? { ...proof(), tokenId: randomUUID() } : proof()]);
      if (mutation === 'duplicate') await client.query('SELECT license_company_finish($1,$2)', [request.id, proof()]);
      if (mutation === 'after') await client.query("INSERT INTO license_catalog(name) VALUES('Unrelated post-finish effect')");
    }), error => error.code === '42501');
  }
  assert.deepEqual(await snapshot(), before);
});

test('retained database receipt validation detects changed catalog, incorrect counters and missing pending receipt even after guards are restored', async () => {
  const product = await assign(await create());
  for (const mutation of ['catalog', 'counter', 'outbox']) {
    await transaction(async client => {
      if (mutation === 'outbox') {
        await client.query('ALTER TABLE license_company_outbox DISABLE TRIGGER USER');
        await client.query('DELETE FROM license_company_outbox WHERE id=(SELECT id FROM license_company_events WHERE license_id=$1 ORDER BY after_revision DESC LIMIT 1)', [product.id]);
        await client.query('ALTER TABLE license_company_outbox ENABLE TRIGGER USER');
      } else {
        await client.query('ALTER TABLE license_catalog DISABLE TRIGGER USER');
        await client.query(mutation === 'counter' ? 'UPDATE license_catalog SET used_seats=0 WHERE id=$1' : "UPDATE license_catalog SET name='Corrupted catalog behind disabled owner guards' WHERE id=$1", [product.id]);
        await client.query('ALTER TABLE license_catalog ENABLE TRIGGER USER');
      }
      assert.equal((await client.query('SELECT license_company_pool_valid($1) AS valid', [product.id])).rows[0].valid, false);
      await client.query('ROLLBACK'); await client.query('BEGIN');
    });
  }
  assert.equal((await pool.query('SELECT license_company_pool_valid($1) AS valid', [product.id])).rows[0].valid, true);
});

test('physical transaction deadline after successful finish still rolls back catalog and all pending evidence', async () => {
  const before = await snapshot(); const source = proof(); source.validUntil = Math.floor(Date.now() / 1000) + 2;
  await assert.rejects(transaction(async client => {
    const request = command(); await begin(client, source, request); await catalog(client, source, request);
    await client.query('SELECT license_company_finish($1,$2)', [request.id, source]);
    await client.query('SELECT pg_sleep(GREATEST(0,$1::double precision-extract(epoch FROM clock_timestamp()))+0.05)', [source.validUntil]);
  }), error => error.code === '42501');
  assert.deepEqual(await snapshot(), before);
});

test('an inactive or foreign provider cannot be attached and original PIM/review control contexts cannot become company authority', async () => {
  const product = await create(); const before = await snapshot();
  for (const control of ['opendirectory.scope_pool', 'opendirectory.scope_proof', 'opendirectory.policy_configuration', 'opendirectory.policy_publication', 'opendirectory.group_snapshot']) {
    await assert.rejects(transaction(async client => {
      await client.query('SELECT set_config($1,$2,true)', [control, control.endsWith('pool') ? randomUUID() : '{}']);
      await begin(client, proof(), command());
    }), error => error.code === '42501');
  }
  await assert.rejects(pool.query("INSERT INTO license_group_rules(license_id,group_id,configured_by) VALUES($1,$2,$3)", [product.id, randomUUID(), fixture.source.actorUserId]), error => ['23514', '42501'].includes(error.code));
  await assert.rejects(pool.query("INSERT INTO license_requests(license_id,requester_id) VALUES($1,$2)", [product.id, fixture.source.actorUserId]), error => error.code === '42501');
  assert.deepEqual(await snapshot(), before);
});

test('independent actual human actors share the one catalog lock and cannot overbook a single finite seat', async () => {
  const product = await create(1);
  const second = serverFixture(); second.source.tenant = fixture.source.tenant;
  const other = new CompanyLicenses(allocator, { authority: second.authority });
  const results = await Promise.allSettled([
    assign(product),
    other.assign(product.id, { userId: second.ownUser, confirm: true, reason: 'Independently reviewed second company caller' }, poolEtag(product), second.user, bearer),
  ]);
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
  const failure = results.find(result => result.status === 'rejected').reason;
  assert.ok(failure.code === '40001' || failure.status === 412, JSON.stringify({ code: failure.code, status: failure.status, message: failure.message }));
  const current = await companies.get(product.id, fixture.user, bearer);
  assert.equal(current.revision, '2'); assert.equal(current.usedSeats, 1); assert.equal(current.availableSeats, 0);
  const succeeded = results[0].status === 'fulfilled' ? fixture : second;
  const failed = succeeded === fixture ? second : fixture;
  const failedService = failed === fixture ? companies : other;
  const before = await snapshot();
  await assert.rejects(failedService.assign(product.id, { userId: failed.ownUser, confirm: true, reason: 'Reviewed retry against now exhausted local capacity' }, poolEtag(current), failed.user, bearer), error => error.status === 409);
  assert.deepEqual(await snapshot(), before);
  assert.equal((await pool.query('SELECT count(*)::integer AS count FROM license_assignments WHERE license_id=$1', [product.id])).rows[0].count, 1);
  assert.equal((await pool.query('SELECT count(*)::integer AS count FROM license_subjects WHERE user_id=$1', [failed.ownUser])).rows[0].count, 0);
});

test('the original authority deadline is enforced after a proven actual catalog row lock wait', async () => {
  const product = await create(); const before = await snapshot(); const blocker = await pool.connect();
  let notify; const entered = new Promise(resolve => { notify = resolve; }); let pending;
  try {
    await blocker.query('BEGIN'); await blocker.query('SELECT id FROM license_catalog WHERE id=$1 FOR UPDATE', [product.id]);
    fixture.source.validUntil = Math.floor(Date.now() / 1000) + 2;
    fixture.beforeQuery = async (client, sql) => {
      if (sql.startsWith('SELECT license_company_begin')) notify((await client.query('SELECT pg_backend_pid() AS pid')).rows[0].pid);
    };
    pending = assign(product).then(value => ({ value }), error => ({ error }));
    const pid = await entered; let blocked = false;
    for (let attempt = 0; attempt < 100; attempt++) {
      blocked = (await pool.query('SELECT cardinality(pg_blocking_pids($1))>0 AS blocked', [pid])).rows[0].blocked;
      if (blocked) break;
      await new Promise(resolve => setTimeout(resolve, 5));
    }
    assert.equal(blocked, true, 'The exact company begin backend must be waiting behind the held actual pool row');
    await blocker.query('SELECT pg_sleep(GREATEST(0,$1::double precision-extract(epoch FROM clock_timestamp()))+0.05)', [fixture.source.validUntil]);
    await blocker.query('COMMIT');
    const result = await pending;
    assert.equal(result.error?.code, '42501');
  } finally { await blocker.query('ROLLBACK'); blocker.release(); if (pending) await pending; }
  assert.deepEqual(await snapshot(), before);
});

test('the existing original eligibility incarnation stays exact through the full positive PostgreSQL BIGINT boundary', async () => {
  const maximum = '9223372036854775807';
  fixture.targets.set(fixture.ownUser, { id: fixture.ownUser, revision: maximum, eligibilityRevision: maximum, enabled: true, deleted: false });
  const product = await assign(await create());
  assert.equal(product.revision, '2');
  const rows = (await pool.query('SELECT assignment.eligibility_revision,grants.eligibility_revision AS grant_revision FROM license_assignments assignment JOIN license_assignment_sources source ON source.license_id=assignment.license_id AND source.user_id=assignment.assignee_id JOIN license_grants grants ON grants.id=source.grant_id WHERE assignment.license_id=$1', [product.id])).rows;
  assert.deepEqual(rows, [{ eligibility_revision: maximum, grant_revision: maximum }]);
  const event = (await pool.query('SELECT after_state,proof FROM license_company_events WHERE type=$1', ['app.license.assigned'])).rows[0];
  assert.equal(event.after_state.assignment.eligibility_revision, maximum);
  assert.equal(event.after_state.grant.eligibility_revision, maximum);
  assert.equal(event.proof.source.target.eligibilityRevision, maximum);
});

test('the source withdrawn after actual assignment SQL and before final receiving cannot leave a seat or a revised pool', async () => {
  const product = await create(); const before = await snapshot();
  fixture.beforeQuery = async (_client, sql) => {
    if (sql.startsWith('INSERT INTO license_audit_events') && sql.includes('actor_issuer')) fixture.revoked = true;
  };
  await assert.rejects(assign(product), error => error.status === 401);
  assert.deepEqual(await snapshot(), before);
});

test('all retained original event origins and pending receipts are required for reads, including prior assignment history', async () => {
  const assigned = await assign(await create()); const allocation = (await companies.assignments(assigned.id, {}, fixture.user, bearer)).assignments[0];
  const product = await revoke(assigned, allocation);
  for (const relation of ['license_company_origins', 'license_company_outbox', 'license_audit_events']) {
    await transaction(async client => {
      await client.query('ALTER TABLE ' + relation + ' DISABLE TRIGGER USER');
      if (relation === 'license_company_origins') await client.query("DELETE FROM license_company_origins WHERE command_id=(SELECT id FROM license_company_events WHERE type='app.license.assigned')");
      if (relation === 'license_company_outbox') await client.query("DELETE FROM license_company_outbox WHERE id=(SELECT id FROM license_company_events WHERE type='app.license.assigned')");
      if (relation === 'license_audit_events') await client.query("DELETE FROM license_audit_events WHERE action='assigned'");
      await client.query('ALTER TABLE ' + relation + ' ENABLE TRIGGER USER');
      assert.equal((await client.query('SELECT license_company_pool_valid($1) AS valid', [product.id])).rows[0].valid, false);
      await client.query('ROLLBACK'); await client.query('BEGIN');
    });
  }
  assert.equal((await pool.query('SELECT license_company_pool_valid($1) AS valid', [product.id])).rows[0].valid, true);
});

test('a durable receipt is distinct from supported governance so an unsupported controlled pool returns 409, never bypasses PIM and never appears newly allocated', async () => {
  const product = await create();
  await pool.query('ALTER TABLE license_scope_activation_policies DISABLE TRIGGER USER');
  await pool.query("INSERT INTO license_scope_activation_policies(license_id,duty,version,activation_required,max_duration_seconds,prepared_eligibility_ids,updated_by) VALUES($1,'allocator',2,false,300,'{}',$2)", [product.id, fixture.source.actorUserId]);
  await pool.query('ALTER TABLE license_scope_activation_policies ENABLE TRIGGER USER');
  assert.equal((await pool.query('SELECT license_company_pool_valid($1) AS valid', [product.id])).rows[0].valid, true);
  const before = await snapshot();
  await assert.rejects(assign(product), error => error.status === 409);
  await assert.rejects(transaction(client => begin(client, proof('assign'), command('assign', product))), error => error.code === '23514');
  assert.deepEqual(await snapshot(), before);
});

test('an actual preexisting provider subject prevents adoption before any provider fan-out or canonical directory reset', async () => {
  await transaction(async client => {
    await client.query("SELECT set_config('opendirectory.provider_actor','{\"kind\":\"explicit-offline-fixture\"}',true),set_config('opendirectory.provider_reason','Explicit reviewed prior provider binding',true)");
    const connector = (await client.query('INSERT INTO license_provider_connectors(tenant_id) VALUES($1) RETURNING id', [randomUUID()])).rows[0];
    await client.query('INSERT INTO license_provider_subjects(connector_id,user_id,object_id) VALUES($1,$2,$3)', [connector.id, fixture.ownUser, randomUUID()]);
  });
  const product = await create(); const before = await snapshot();
  await assert.rejects(assign(product), error => error.code === '23514');
  assert.deepEqual(await snapshot(), before);
  assert.equal((await pool.query('SELECT count(*)::integer AS count FROM license_fulfillment_targets')).rows[0].count, 0);
});

test('the private SQL interfaces reject a separately authenticated SQL login even when explicitly granted execution', async () => {
  const role = 'company_limited_' + randomUUID().replaceAll('-', ''); roles.push(role);
  await administration.query('CREATE ROLE ' + role + ' LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOINHERIT');
  await pool.query('GRANT USAGE ON SCHEMA ' + schema + ' TO ' + role);
  await pool.query('GRANT EXECUTE ON FUNCTION license_company_begin(jsonb,jsonb),license_company_finish(uuid,jsonb),license_company_receiving(),license_company_pool_valid(uuid) TO ' + role);
  const url = new URL(process.env.LICENSE_TEST_DATABASE_URL); url.username = role; url.searchParams.set('options', '-c search_path=' + schema + ',public');
  const restricted = new Pool({ connectionString: url.toString(), max: 1 });
  try {
    await assert.rejects(restricted.query('SELECT license_company_begin($1,$2)', [proof(), command()]), error => error.code === '42501');
    await assert.rejects(restricted.query('SELECT license_company_finish($1,$2)', [randomUUID(), proof()]), error => error.code === '42501');
  } finally { await restricted.end(); }
  await assert.rejects(transaction(async client => {
    const owner = (await client.query('SELECT current_user AS name')).rows[0].name;
    await client.query('SET LOCAL ROLE ' + owner); await begin(client, proof(), command());
  }), error => error.code === '42501');
  assert.equal((await pool.query('SELECT count(*)::integer AS count FROM license_company_commands')).rows[0].count, 0);
});

test('original owned subject lineage cannot be used in an unrelated global pool by raw source insertion', async () => {
  await assign(await create());
  const product = (await pool.query("INSERT INTO license_catalog(name,total_seats) VALUES('Separate global catalog',2) RETURNING id")).rows[0];
  const before = await snapshot();
  await assert.rejects(pool.query("INSERT INTO license_assignment_sources(license_id,user_id,source_type,source_id,assigned_by) VALUES($1,$2,'direct','direct','unscoped-global-actor')", [product.id, fixture.ownUser]), error => error.code === '42501');
  assert.deepEqual(await snapshot(), before);
});

test('an older scope inserted after begin cannot borrow the new original receipt functions or extend a completed source', async () => {
  const before = await snapshot();
  for (const control of ['opendirectory.scope_pool', 'opendirectory.policy_configuration', 'opendirectory.provider_actor', 'opendirectory.capacity_protocol']) {
    await assert.rejects(transaction(async client => {
      const request = command(); await begin(client, proof(), request); await catalog(client, proof(), request);
      await client.query('SELECT set_config($1,$2,true)', [control, control.endsWith('pool') ? randomUUID() : '{}']);
      await client.query('SELECT license_company_finish($1,$2)', [request.id, proof()]);
    }), error => error.code === '42501');
  }
  assert.deepEqual(await snapshot(), before);
});

test('direct original-command inserts cannot hide earlier SQL effects behind a manually set command GUC', async () => {
  const before = await snapshot();
  await assert.rejects(transaction(async client => {
    const request = command(); const source = proof();
    await client.query("INSERT INTO license_catalog(name) VALUES('Original earlier unscoped actual mutation')");
    await client.query("SELECT set_config('opendirectory.license_company',$1,true)", [request.id]);
    await client.query("INSERT INTO license_company_commands(id,correlation_id,license_id,tenant_id,actor_user_id,target_user_id,action,source,command,before_state,created_at,valid_until,transaction_id) VALUES($1,$2,$3,$4,$5,NULL,'create',$6,$7,license_company_state($3,$5,NULL),clock_timestamp(),to_timestamp($8),txid_current())",
      [request.id, request.correlationId, request.licenseId, source.tenant.id, source.actorUserId, source, request, source.validUntil]);
  }), error => error.code === '42501');
  assert.deepEqual(await snapshot(), before);
});

test('pool edits grow occupied stock, rename metadata and shrink to the actual floor without changing allocation or external resources', async () => {
  const first = await assign(await create(2)); const secondUser = randomUUID();
  fixture.targets.set(secondUser, { id: secondUser, revision: '1', eligibilityRevision: '1', enabled: true, deleted: false });
  const occupied = await assign(first, secondUser); const before = await snapshot();
  const grown = await update(occupied, { name: 'Renamed Native Company App', vendor: 'Updated Native Vendor', description: 'Reviewed local stock only', totalSeats: 5 });
  assert.equal(grown.revision, '4'); assert.equal(grown.usedSeats, 2); assert.equal(grown.availableSeats, 3); assert.equal(grown.allocationMode, 'local-only');
  const shrunk = await update(grown, { name: grown.name, totalSeats: 2 });
  assert.equal(shrunk.revision, '5'); assert.equal(shrunk.usedSeats, 2); assert.equal(shrunk.availableSeats, 0);
  const after = await snapshot();
  for (const relation of ['license_subjects', 'license_assignments', 'license_assignment_sources', 'license_grants', 'license_grant_events']) assert.deepEqual(after[relation], before[relation], relation);
  for (const relation of ['license_provider_connectors', 'license_provider_products', 'license_provider_subjects', 'license_fulfillment_targets', 'license_fulfillment_changes', 'license_capacity_sources', 'license_capacity_runs', 'license_capacity_budgets']) {
    assert.equal((await pool.query('SELECT count(*)::integer AS count FROM ' + relation)).rows[0].count, 0, relation);
  }
  const baseline = await snapshot();
  await assert.rejects(update(shrunk, { totalSeats: 1 }), error => error.status === 409 || error.code === '23514');
  await assert.rejects(transaction(client => begin(client, proof('update'), command('update', shrunk, { values: updateValues(shrunk, { totalSeats: 1 }) }))), error => error.code === '23514');
  assert.deepEqual(await snapshot(), baseline);
  const event = (await pool.query("SELECT event.*,outbox.status,license_company_event_valid(event) AS valid FROM license_company_events event JOIN license_company_outbox outbox USING(id) WHERE event.type='app.license.pool.updated' ORDER BY event.after_revision LIMIT 1")).rows[0];
  assert.equal(event.valid, true); assert.equal(event.status, 'pending'); assert.equal(event.target_user_id, null);
  assert.equal(event.proof.command.action, 'update'); assert.equal(event.proof.command.expectedVersion, '3'); assert.equal(event.proof.command.assignmentId, null);
  assert.deepEqual(event.proof.command.values, updateValues(grown)); assert.deepEqual(event.proof.source.permissions, COMPANY_LICENSE_PERMISSIONS);
  assert.equal(event.proof.source.target, null); assert.deepEqual(event.proof.source, event.proof.checkpoint);
  const effects = (await pool.query('SELECT relation,operation,before_state,after_state FROM license_company_origins WHERE command_id=$1 ORDER BY ordinal', [event.id])).rows;
  assert.deepEqual(effects.map(effect => [effect.relation, effect.operation]), [['license_catalog', 'UPDATE'], ['license_audit_events', 'INSERT'], ['license_catalog', 'UPDATE']]);
  assert.equal(effects[0].before_state.used_seats, 2); assert.equal(effects[0].after_state.used_seats, 2);
  assert.deepEqual(effects[1].after_state.details, { before: updateValues(occupied), after: updateValues(grown), reason: event.proof.command.reason });
  assert.equal((await companies.editCapabilities(shrunk.id, fixture.user, bearer)).poolRevision, '5');
  assert.equal((await companies.history(shrunk.id, {}, fixture.user, bearer)).total, 5);
});

test('pool edits neither adopt an absent actor subject nor wait on existing subject row locks', async () => {
  const empty = await update(await create());
  assert.equal((await pool.query('SELECT count(*)::integer AS count FROM license_subjects')).rows[0].count, 0);
  const occupied = await assign(empty); const before = await snapshot(); const blocker = await pool.connect();
  try {
    await blocker.query('BEGIN'); await blocker.query('SELECT user_id FROM license_subjects FOR UPDATE');
    const edited = await update(occupied, { totalSeats: 3 });
    assert.equal(edited.revision, '4'); assert.equal(edited.usedSeats, 1);
    assert.deepEqual((await snapshot()).license_subjects, before.license_subjects);
  } finally { await blocker.query('ROLLBACK'); blocker.release(); }
  const commands = (await pool.query("SELECT new_subject_ids FROM license_company_commands WHERE action='update'")).rows;
  assert.ok(commands.every(receipt => receipt.new_subject_ids.length === 0));
});

for (const history of ['global-audit', 'forged-owned-audit', 'foreign-audit', 'provider-history']) {
  test('edit-first subject adoption still rejects unrelated ' + history + ' instead of trusting an audit actor or UUID match', async () => {
    let product = await update(await create());
    if (history === 'global-audit' || history === 'forged-owned-audit') {
      if (history === 'forged-owned-audit') await pool.query('ALTER TABLE license_audit_events DISABLE TRIGGER USER');
      await pool.query("INSERT INTO license_audit_events(license_id,action,actor,details,actor_issuer,actor_subject) SELECT $1,action,actor,details,actor_issuer,actor_subject FROM license_audit_events WHERE action='pool-updated' LIMIT 1", [history === 'global-audit' ? null : product.id]);
      if (history === 'forged-owned-audit') await pool.query('ALTER TABLE license_audit_events ENABLE TRIGGER USER');
    }
    if (history === 'foreign-audit') { fixture.source.tenant.id = randomUUID(); product = await create(); }
    if (history === 'provider-history') {
      await transaction(async client => {
        await client.query("SELECT set_config('opendirectory.provider_actor','{\"kind\":\"explicit-offline-fixture\"}',true),set_config('opendirectory.provider_reason','Explicit reviewed prior actor provider binding',true)");
        const connector = (await client.query('INSERT INTO license_provider_connectors(tenant_id) VALUES($1) RETURNING id', [randomUUID()])).rows[0];
        await client.query('INSERT INTO license_provider_subjects(connector_id,user_id,object_id) VALUES($1,$2,$3)', [connector.id, fixture.source.actorUserId, randomUUID()]);
      });
    }
    const before = await snapshot(); await assert.rejects(assign(product), error => error.code === '23514');
    assert.deepEqual(await snapshot(), before); assert.equal(before.license_subjects.length, 0);
  });
}

test('pool edit no-ops and malformed exact update commands leave no SQL admission or effects', async () => {
  const product = await assign(await create()); const before = await snapshot();
  await assert.rejects(update(product, { name: product.name }), error => error.status === 409 || error.code === '23514');
  await assert.rejects(transaction(client => begin(client, proof('update'), command('update', product, { values: updateValues(product) }))), error => error.code === '23514');
  for (const changes of [
    { expectedVersion: '0' }, { expectedVersion: 2 }, { expectedVersion: '02' }, { expectedVersion: '9223372036854775808' },
    { assignmentId: randomUUID() }, { values: null }, { values: updateValues(product, { extra: true }) },
    ...[0, 10001, 1.5, '2'].map(totalSeats => ({ values: updateValues(product, { totalSeats }) })),
  ]) await assert.rejects(transaction(client => begin(client, proof('update'), command('update', product, changes))), error => error.code === '42501');
  for (const source of [{ ...proof('update'), target: fixture.targets.get(fixture.ownUser) }, { ...proof('update'), permissions: [...COMPANY_LICENSE_PERMISSIONS, 'company.apps.update'] }]) {
    await assert.rejects(transaction(client => begin(client, source, command('update', product))), error => error.code === '42501');
  }
  assert.deepEqual(await snapshot(), before);
});

for (const competitor of ['update', 'assign']) {
  test('parallel pool edit and ' + competitor + ' share the canonical row lock and accept exactly one captured version', async () => {
    const product = await create(2); const second = serverFixture(); second.source.tenant = fixture.source.tenant;
    const other = new CompanyLicenses(allocator, { authority: second.authority });
    const alternate = competitor === 'update'
      ? () => other.update(product.id, { ...updateValues(product, { name: 'Independent parallel metadata' }), confirm: true, reason: 'Independent captured native edit review' }, poolEtag(product), second.user, bearer)
      : () => other.assign(product.id, { userId: second.ownUser, confirm: true, reason: 'Independent captured native assignment review' }, poolEtag(product), second.user, bearer);
    const results = await Promise.allSettled([update(product, { totalSeats: 3 }), alternate()]);
    assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
    const failure = results.find(result => result.status === 'rejected').reason;
    assert.ok(failure.status === 412 || failure.code === '40001', JSON.stringify({ code: failure.code, status: failure.status, message: failure.message }));
    const current = await companies.get(product.id, fixture.user, bearer);
    assert.equal(current.revision, '2'); assert.equal((await companies.history(product.id, {}, fixture.user, bearer)).total, 2);
    const before = await snapshot(); await assert.rejects(update(product), error => error.status === 412 || error.code === '40001');
    assert.deepEqual(await snapshot(), before);
  });
}

test('foreign pool edit targets fail before any recipient lookup or company effect', async () => {
  const product = await create(); const before = await snapshot(); fixture.source.tenant.id = randomUUID(); fixture.calls = [];
  await assert.rejects(update(product), error => error.status === 404);
  await assert.rejects(companies.editCapabilities(product.id, fixture.user, bearer), error => error.status === 404);
  await assert.rejects(transaction(client => begin(client, proof('update'), command('update', product))), error => error.code === '42501');
  assert.ok(fixture.calls.every(call => call.targetId === null)); assert.deepEqual(await snapshot(), before);
});

for (const [relation, operation] of [['license_catalog', 'UPDATE'], ['license_audit_events', 'INSERT'], ['license_company_origins', 'INSERT'], ['license_company_events', 'INSERT'], ['license_company_outbox', 'INSERT']]) {
  test('suppressed pool edit effect on ' + relation + ' rolls back metadata, stock, revision and every receipt', async () => {
    const product = await assign(await create());
    await pool.query('CREATE FUNCTION native_suppress_edit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL;END;$$');
    await pool.query('CREATE TRIGGER aaa_native_suppress_edit BEFORE ' + operation + ' ON ' + relation + ' FOR EACH ROW EXECUTE FUNCTION native_suppress_edit()');
    const before = await snapshot(); await assert.rejects(update(product, { totalSeats: 4 })); assert.deepEqual(await snapshot(), before);
  });
}

test('pool edit authority withdrawn after actual metadata DML cannot commit its audit or catalog effect', async () => {
  const product = await assign(await create()); const before = await snapshot(); let observed = false;
  fixture.beforeQuery = async (client, sql) => {
    if (sql.startsWith('INSERT INTO license_audit_events') && companyLicenseContext.getStore()?.action === 'update') {
      const current = (await client.query('SELECT name,business_revision FROM license_catalog WHERE id=$1', [product.id])).rows[0];
      assert.equal(current.name, product.name + ' Edited'); assert.equal(current.business_revision, product.revision); observed = true; fixture.revoked = true;
    }
  };
  await assert.rejects(update(product), error => error.status === 401); assert.equal(observed, true); assert.deepEqual(await snapshot(), before);
});

test('pool edit physical commit rechecks expiry after successful finish and rolls back all three effects', async () => {
  const product = await assign(await create()); const before = await snapshot(); const source = proof('update'); source.validUntil = Math.floor(Date.now() / 1000) + 2;
  await assert.rejects(transaction(async client => {
    const request = command('update', product); await begin(client, source, request); await editCatalog(client, source, request);
    assert.equal((await client.query('SELECT license_company_finish($1,$2) AS id', [request.id, source])).rows[0].id, request.id);
    assert.equal((await client.query('SELECT license_company_pool_valid($1) AS valid', [product.id])).rows[0].valid, true);
    await client.query('SELECT pg_sleep(GREATEST(0,$1::double precision-extract(epoch FROM clock_timestamp()))+0.05)', [source.validUntil]);
  }), error => error.code === '42501');
  assert.deepEqual(await snapshot(), before);
});

test('pool edit expiry after a proven canonical catalog lock wait cannot admit metadata or subjects', async () => {
  const product = await create(); const before = await snapshot(); const blocker = await pool.connect(); let pending; let notify;
  const entered = new Promise(resolve => { notify = resolve; });
  try {
    await blocker.query('BEGIN'); await blocker.query('SELECT id FROM license_catalog WHERE id=$1 FOR UPDATE', [product.id]);
    fixture.source.validUntil = Math.floor(Date.now() / 1000) + 2;
    fixture.beforeQuery = async (client, sql) => {
      if (sql.startsWith('SELECT license_company_begin')) notify((await client.query('SELECT pg_backend_pid() AS pid')).rows[0].pid);
    };
    pending = update(product).then(value => ({ value }), error => ({ error })); const pid = await entered; let blocked = false;
    for (let attempt = 0; attempt < 100; attempt += 1) {
      blocked = (await pool.query('SELECT cardinality(pg_blocking_pids($1))>0 AS blocked', [pid])).rows[0].blocked;
      if (blocked) break;
      await new Promise(resolve => setTimeout(resolve, 5));
    }
    assert.equal(blocked, true);
    await blocker.query('SELECT pg_sleep(GREATEST(0,$1::double precision-extract(epoch FROM clock_timestamp()))+0.05)', [fixture.source.validUntil]);
    await blocker.query('COMMIT'); assert.equal((await pending).error?.code, '42501');
  } finally { await blocker.query('ROLLBACK'); blocker.release(); if (pending) await pending; }
  assert.deepEqual(await snapshot(), before);
});

test('a physically suppressed pool edit revision at finish cannot retain metadata or acknowledge a pending receipt', async () => {
  const product = await assign(await create()); const before = await snapshot();
  await pool.query('CREATE FUNCTION native_suppress_edit_revision() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.business_revision IS DISTINCT FROM OLD.business_revision THEN RETURN NULL;END IF;RETURN NEW;END;$$');
  await pool.query('CREATE TRIGGER aaa_native_suppress_edit_revision BEFORE UPDATE ON license_catalog FOR EACH ROW EXECUTE FUNCTION native_suppress_edit_revision()');
  await assert.rejects(update(product, { totalSeats: 3 }), error => error.code === '40001'); assert.deepEqual(await snapshot(), before);
});

test('pool edit receiving rejects missing migration, changed constraints, replica execution and every downgraded retained function', async () => {
  const product = await create(); const before = await snapshot();
  const mutations = [
    "DELETE FROM license_schema_versions WHERE version=24",
    'ALTER TABLE license_company_commands DROP CONSTRAINT license_company_commands_action_check',
    'ALTER TABLE license_company_events DROP CONSTRAINT license_company_events_type_check',
    'ALTER TABLE license_catalog DROP CONSTRAINT license_company_edit_stock',
    "SET LOCAL session_replication_role='replica'",
  ];
  const original = fs.readFileSync(path.join(migrations, '022_company_licenses.sql'), 'utf8');
  for (const name of ['license_company_subject_unused', 'license_company_proof_valid', 'license_company_guard', 'license_company_begin', 'license_company_finish', 'license_company_event_valid', 'license_company_pool_valid']) {
    const start = original.indexOf('CREATE OR REPLACE FUNCTION ' + name + '('); const end = original.indexOf('\nEND; $$;', start) + '\nEND; $$;'.length;
    assert.ok(start >= 0 && end > start); mutations.push(original.slice(start, end));
  }
  for (const mutation of mutations) {
    await assert.rejects(transaction(async client => { await client.query(mutation); await client.query('SELECT license_company_edit_receiving()'); }), error => error.code === '42501', mutation);
  }
  await pool.query('SELECT license_company_edit_receiving()'); assert.deepEqual(await snapshot(), before);
});

test('pool edit retained history survives later assignment, release, expired authority and full migration replay', async () => {
  const original = await assign(await create()); fixture.source.validUntil = Math.floor(Date.now() / 1000) + 2;
  const deadline = fixture.source.validUntil; const edited = await update(original, { totalSeats: 4 });
  fixture.source.validUntil = Math.min(fixture.user.exp, fixture.user.auth_time + 300);
  const assignment = (await companies.assignments(edited.id, {}, fixture.user, bearer)).assignments[0];
  const released = await revoke(edited, assignment); const reassigned = await assign(released);
  const before = await snapshot(); await migrate(); await migrate(); assert.deepEqual(await snapshot(), before);
  assert.equal((await companies.get(edited.id, fixture.user, bearer)).revision, reassigned.revision);
  await pool.query('SELECT pg_sleep(GREATEST(0,$1::double precision-extract(epoch FROM clock_timestamp()))+0.05)', [deadline]);
  const event = (await pool.query("SELECT event.*,license_company_event_valid(event) AS valid FROM license_company_events event WHERE type='app.license.pool.updated'")).rows[0];
  assert.equal(event.proof.source.validUntil, deadline); assert.ok(event.proof.source.validUntil <= Date.now() / 1000); assert.equal(event.valid, true);
  assert.equal((await pool.query('SELECT license_company_pool_valid($1) AS valid', [edited.id])).rows[0].valid, true);
});

for (const mutation of ['edit-origin', 'revision-origin', 'audit', 'pending', 'proof', 'command-proof', 'source-deadline', 'catalog-chain']) {
  test('pool edit reads reject retained ' + mutation + ' corruption even after a later valid command', async () => {
    const edited = await update(await assign(await create()), { totalSeats: 4 }); const latest = await update(edited, { description: 'Later independently retained metadata' });
    const editId = (await pool.query("SELECT id FROM license_company_events WHERE type='app.license.pool.updated' ORDER BY after_revision LIMIT 1")).rows[0].id;
    await transaction(async client => {
      for (const relation of ['license_company_origins', 'license_audit_events', 'license_company_outbox', 'license_company_events', 'license_company_commands']) await client.query('ALTER TABLE ' + relation + ' DISABLE TRIGGER USER');
      if (mutation === 'edit-origin' || mutation === 'revision-origin') await client.query('DELETE FROM license_company_origins WHERE ordinal=(SELECT ordinal FROM license_company_origins WHERE command_id=$1 AND relation=$2 ORDER BY ordinal ' + (mutation === 'edit-origin' ? 'ASC' : 'DESC') + ' LIMIT 1)', [editId, 'license_catalog']);
      if (mutation === 'audit') await client.query("DELETE FROM license_audit_events WHERE id=(SELECT (after_state->>'id')::uuid FROM license_company_origins WHERE command_id=$1 AND relation='license_audit_events')", [editId]);
      if (mutation === 'pending') await client.query('DELETE FROM license_company_outbox WHERE id=$1', [editId]);
      if (mutation === 'proof') await client.query("UPDATE license_company_events SET proof=jsonb_set(proof,'{checkpoint,tokenId}','\"changed-retained-source\"'::jsonb) WHERE id=$1", [editId]);
      if (mutation === 'command-proof') {
        await client.query("UPDATE license_company_commands SET command=jsonb_set(command,'{values,totalSeats}','10001'::jsonb) WHERE id=$1", [editId]);
        await client.query("UPDATE license_company_events event SET proof=jsonb_build_object('source',command.source,'command',command.command,'checkpoint',command.source) FROM license_company_commands command WHERE event.id=command.id AND command.id=$1", [editId]);
      }
      if (mutation === 'source-deadline') {
        await client.query("UPDATE license_company_commands SET source=jsonb_set(source,'{validUntil}','1'::jsonb) WHERE id=$1", [editId]);
        await client.query("UPDATE license_company_events event SET proof=jsonb_build_object('source',command.source,'command',command.command,'checkpoint',command.source) FROM license_company_commands command WHERE event.id=command.id AND command.id=$1", [editId]);
      }
      if (mutation === 'catalog-chain') await client.query("UPDATE license_company_events SET before_state=jsonb_set(before_state,'{catalog,name}','\"Broken predecessor catalog\"'::jsonb) WHERE id=$1", [editId]);
      for (const relation of ['license_company_origins', 'license_audit_events', 'license_company_outbox', 'license_company_events', 'license_company_commands']) await client.query('ALTER TABLE ' + relation + ' ENABLE TRIGGER USER');
      assert.equal((await client.query('SELECT license_company_pool_valid($1) AS valid', [latest.id])).rows[0].valid, false);
      await client.query('ROLLBACK'); await client.query('BEGIN');
    });
    assert.equal((await companies.get(latest.id, fixture.user, bearer)).revision, latest.revision);
  });
}

test('committed corruption of an older pool edit receipt denies list, detail, history, edit capabilities and further writes', async () => {
  const edited = await update(await assign(await create()), { totalSeats: 3 }); const latest = await update(edited, { description: 'Current metadata after an older edit' });
  await pool.query('ALTER TABLE license_company_outbox DISABLE TRIGGER USER');
  await pool.query("DELETE FROM license_company_outbox WHERE id=(SELECT id FROM license_company_events WHERE type='app.license.pool.updated' ORDER BY after_revision LIMIT 1)");
  await pool.query('ALTER TABLE license_company_outbox ENABLE TRIGGER USER'); const before = await snapshot();
  for (const read of [
    () => companies.list({}, fixture.user, bearer), () => companies.get(latest.id, fixture.user, bearer),
    () => companies.history(latest.id, {}, fixture.user, bearer), () => companies.editCapabilities(latest.id, fixture.user, bearer),
    () => update(latest),
  ]) await assert.rejects(read(), error => error.status === 503);
  assert.deepEqual(await snapshot(), before);
});

test('pool edit admission cannot mutate subjects or borrow unrelated grants, governance or provider authority', async () => {
  const product = await assign(await create()); const before = await snapshot();
  for (const operation of [
    client => client.query('UPDATE license_subjects SET updated_at=updated_at WHERE user_id=$1', [fixture.source.actorUserId]),
    client => client.query('INSERT INTO license_subjects(user_id,business_tenant_id) VALUES($1,$2)', [randomUUID(), fixture.source.tenant.id]),
    client => client.query('DELETE FROM license_assignment_sources WHERE license_id=$1', [product.id]),
    client => client.query('DELETE FROM license_assignments WHERE license_id=$1', [product.id]),
    client => client.query('UPDATE license_catalog SET total_seats=0 WHERE id=$1', [product.id]),
    client => client.query('UPDATE license_catalog SET business_revision=business_revision+1 WHERE id=$1', [product.id]),
  ]) {
    await assert.rejects(transaction(async client => { await begin(client, proof('update'), command('update', product)); await operation(client); }), error => ['23514', '42501'].includes(error.code));
  }
  assert.deepEqual(await snapshot(), before);
  await pool.query('ALTER TABLE license_scope_activation_policies DISABLE TRIGGER USER');
  await pool.query("INSERT INTO license_scope_activation_policies(license_id,duty,version,activation_required,max_duration_seconds,prepared_eligibility_ids,updated_by) VALUES($1,'allocator',2,false,300,'{}',$2)", [product.id, fixture.source.actorUserId]);
  await pool.query('ALTER TABLE license_scope_activation_policies ENABLE TRIGGER USER');
  await assert.rejects(update(product), error => error.status === 409);
  await assert.rejects(companies.editCapabilities(product.id, fixture.user, bearer), error => error.status === 409);
  await assert.rejects(transaction(client => begin(client, proof('update'), command('update', product))), error => error.code === '23514');
});

test('read validation rejects a restamped current version with no contiguous immutable origin chain', async () => {
  const product = await create();
  await transaction(async client => {
    await client.query('ALTER TABLE license_catalog DISABLE TRIGGER USER;ALTER TABLE license_company_events DISABLE TRIGGER USER');
    await client.query('UPDATE license_catalog SET business_revision=10 WHERE id=$1', [product.id]);
    await client.query("UPDATE license_company_events SET after_revision=10,after_state=jsonb_set(after_state,'{catalog,business_revision}','\"10\"'::jsonb) WHERE license_id=$1", [product.id]);
    await client.query('ALTER TABLE license_catalog ENABLE TRIGGER USER;ALTER TABLE license_company_events ENABLE TRIGGER USER');
    assert.equal((await client.query('SELECT license_company_pool_valid($1) AS valid', [product.id])).rows[0].valid, false);
    await client.query('ROLLBACK'); await client.query('BEGIN');
  });
});
