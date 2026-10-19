'use strict';

const { test, beforeEach, afterEach, after } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID, createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { Pool } = require('pg');
const { LicenseAllocator } = require('../LicenseAllocator');
const { CompanyLicenses } = require('../CompanyLicenses');
const { CompanyLicenseAuthority } = require('../CompanyLicenseAuthority');
const { CompanyOffboardingJournal } = require('../CompanyOffboardingJournal');
const { COMPANY_LICENSE_PERMISSIONS, poolEtag } = require('../../../../../../packages/company-license-contract');

assert.ok(process.env.LICENSE_TEST_DATABASE_URL, 'Run scripts/test-company-offboarding-journal.js against disposable native PostgreSQL');
const administration = new Pool({ connectionString: process.env.LICENSE_TEST_DATABASE_URL, max: 1 });
const migrations = path.join(__dirname, '../../db/migrations');
const bearer = 'Bearer explicit.company.journal.native.fixture';
let schema; let pool; let database; let journal; let companies; let fixture;

function originalSourceFixture() {
  const authTime = Math.floor(Date.now() / 1000); const actorUserId = randomUUID(); const userId = randomUUID();
  const user = { actor_type: 'user', iss: 'https://company.journal.native.fixture', sub: 'explicit-native-company-owner', jti: randomUUID(), exp: authTime + 3600, auth_time: authTime,
    identity_authorization: { userId: actorUserId, revision: '1', linkRevision: '1', rolesRevision: 'a'.repeat(64) } };
  const source = { schemaVersion: 1, issuer: user.iss, subject: user.sub, tokenId: user.jti, expiresAt: user.exp, context: structuredClone(user.identity_authorization),
    tenant: { id: randomUUID(), version: '1', generation: '1' }, actorUserId, permissions: [...COMPANY_LICENSE_PERMISSIONS], validUntil: authTime + 300, target: null };
  const target = { id: userId, revision: '1', eligibilityRevision: '1', enabled: true, deleted: false };
  const authority = new CompanyLicenseAuthority({ endpoint: 'https://company.journal.native.fixture/api/identity/company-licenses', fetchImpl: async (endpoint, request) => {
    assert.equal(endpoint.href, 'https://company.journal.native.fixture/api/identity/company-licenses'); assert.equal(request.headers.Authorization, bearer);
    assert.equal(request.redirect, 'error'); assert.equal(request.cache, 'no-store');
    const targetId = request.method === 'POST' ? JSON.parse(request.body).userId : null;
    const status = targetId !== null && targetId !== userId ? 404 : 200;
    return new Response(JSON.stringify(status === 200 ? { ...source, target: targetId === null ? null : target } : { error: 'Explicit fixture rejects foreign target' }), { status, headers: { 'content-type': 'application/json' } });
  } });
  return { user, source, target, userId, authority };
}
async function migrate() {
  const names = fs.readdirSync(migrations).filter(name => /^0(0[1-9]|1[0-9]|2[0-3])_.*\.sql$/u.test(name)).sort();
  assert.equal(names.length, 22); assert.equal(names[0], '001_policies.sql'); assert.equal(names.at(-1), '023_company_offboarding.sql');
  for (const name of names) await pool.query(fs.readFileSync(path.join(migrations, name), 'utf8'));
}
async function source() { return fixture.authority.read(bearer, fixture.user, fixture.userId); }
function intent(changes = {}) { return { workflowId: randomUUID(), userId: fixture.userId, userRevision: fixture.target.revision, eligibilityRevision: fixture.target.eligibilityRevision, reason: 'Explicitly confirmed company employee departure', confirm: true, ...changes }; }
async function verify(client) { assert.equal((await client.query('SELECT current_setting(\'transaction_read_only\') AS setting')).rows[0].setting, 'off'); }
async function createJob(request = intent()) { return (await journal.create(database, await source(), request, verify)).job; }
function receipt(job) {
  return { schemaVersion: 1, workflowId: job.id, tenantId: job.tenantId, userId: job.userId, actorUserId: fixture.source.actorUserId, operationId: randomUUID(), action: 'disabled',
    beforeRevision: job.state.requestedRevision, afterRevision: (BigInt(job.state.requestedRevision) + 79n).toString(), beforeEligibilityRevision: job.intent.eligibilityRevision,
    afterEligibilityRevision: (BigInt(job.intent.eligibilityRevision) + 83n).toString(), createdAt: new Date().toISOString(), deliveryStatus: 'pending' };
}
async function checkpoint(job, items = null) {
  const identity = receipt(job); fixture.target.revision = identity.afterRevision; fixture.target.eligibilityRevision = identity.afterEligibilityRevision; fixture.target.enabled = false;
  return journal.save(database, await source(), job, { ...job.state, phase: 'licenses', checkpoint: identity, items }, verify);
}
async function capture(job) {
  const preview = await companies.returnPreview(fixture.userId, {}, fixture.user, bearer);
  const items = preview.assignments.map(item => ({ poolId: item.poolId, assignmentId: item.id, grantId: item.grantId, poolRevision: item.poolRevision, name: item.name, vendor: item.vendor, status: 'pending', eventId: null }));
  return journal.save(database, await source(), job, { ...job.state, items }, verify);
}
async function allocated(count = 1) {
  for (let index = 0; index < count; index += 1) {
    const product = await companies.create({ name: 'Actual retained native pool ' + index, vendor: 'Journal native vendor', description: '', totalSeats: 2, reason: 'Explicit native company stock review' }, fixture.user, bearer);
    await companies.assign(product.id, { userId: fixture.userId, confirm: true, reason: 'Explicit actual native allocation review' }, poolEtag(product), fixture.user, bearer);
  }
}
async function release(job, correlationId = job.id) {
  const item = job.state.items[0]; const product = await companies.get(item.poolId, fixture.user, bearer);
  await companies.revoke(product.id, item.assignmentId, { userId: fixture.userId, confirm: true, reason: 'Confirmed actual native offboarding release' }, poolEtag(product), fixture.user, bearer, correlationId, await source());
  return (await pool.query("SELECT * FROM license_company_events WHERE license_id=$1 AND target_user_id=$2 AND type='app.license.released' ORDER BY after_revision DESC", [item.poolId, job.userId])).rows[0];
}
async function transaction(operation) {
  const client = await pool.connect();
  try { await client.query('BEGIN'); const result = await operation(client); await client.query('COMMIT'); return result; }
  catch (error) { await client.query('ROLLBACK'); throw error; } finally { client.release(); }
}
async function rawState(job, state, changes = '') {
  return transaction(async client => {
    await client.query("SELECT set_config('opendirectory.company_offboarding_source',$1,true)", [JSON.stringify(await source())]);
    await client.query('UPDATE company_offboarding_jobs SET state=$1,revision=revision+1' + changes + ' WHERE tenant_id=$2 AND id=$3', [state, job.tenantId, job.id]);
  });
}
beforeEach(async () => {
  schema = 'company_journal_' + randomUUID().replaceAll('-', ''); await administration.query('CREATE SCHEMA ' + schema);
  const url = new URL(process.env.LICENSE_TEST_DATABASE_URL); url.searchParams.set('options', '-c search_path=' + schema + ',public -c timezone=UTC');
  pool = new Pool({ connectionString: url.toString(), max: 10 }); await migrate(); fixture = originalSourceFixture();
  database = { query: (...args) => pool.query(...args), getClient: () => pool.connect() };
  journal = new CompanyOffboardingJournal(database); companies = new CompanyLicenses(new LicenseAllocator(database), { authority: fixture.authority });
});
afterEach(async () => { await pool?.end(); await administration.query('DROP SCHEMA IF EXISTS ' + schema + ' CASCADE'); });
after(async () => administration.end());

test('all 001–023 migrations apply, 023 repeats without deleting retained jobs, and historic 022 is unchanged', async () => {
  const job = await createJob(); const sql = fs.readFileSync(path.join(migrations, '023_company_offboarding.sql'), 'utf8');
  await pool.query(sql); await journal.ready(); assert.deepEqual(await journal.load(database, job.tenantId, job.id), job);
  assert.equal(createHash('sha256').update(fs.readFileSync(path.join(migrations, '022_company_licenses.sql'))).digest('hex'), '9a423cfc05b1cd677d9332caf35b364a36fbec2a151ba74e181d2d42737d27e1');
  assert.equal((await pool.query("SELECT 'company_offboarding_jobs'=ANY(license_company_relations()) AS mixed")).rows[0].mixed, false);
});

test('caller workflow IDs are tenant scoped; identical replay has no new effects; changed intent conflicts', async () => {
  const request = intent(); const created = await journal.create(database, await source(), request, verify);
  assert.equal(created.created, true); assert.equal(created.job.revision, '1');
  assert.deepEqual(Object.keys(created.job).sort(), ['id', 'tenantId', 'userId', 'createdBy', 'revision', 'intent', 'state', 'createdAt', 'updatedAt'].sort());
  assert.deepEqual(created.job.state, { phase: 'pending', requestedRevision: '1', checkpoint: null, items: null, failure: null });
  assert.deepEqual(await journal.create(database, await source(), structuredClone(request), verify), { job: created.job, created: false });
  await assert.rejects(journal.create(database, await source(), { ...request, reason: 'Different explicit company departure reason' }, verify), error => error.status === 409);
  const foreignTenant = randomUUID(); assert.equal(await journal.load(database, foreignTenant, request.workflowId), null);
  const foreignSource = { ...await source(), tenant: { ...fixture.source.tenant, id: foreignTenant } };
  const second = await journal.create(database, foreignSource, request, verify); assert.equal(second.created, true); assert.equal(second.job.id, created.job.id);
  assert.equal((await journal.list(database, foreignTenant, {})).total, 1);
  assert.equal((await journal.history(database, created.job.tenantId, created.job.id, {})).total, 1);
});

test('dedicated session exclusion survives commits and scopes the same workflow UUID separately by tenant', async () => {
  const job = await createJob(); const first = await journal.lock(job.tenantId, job.id);
  try {
    assert.equal((await first.client.query('SELECT state FROM pg_stat_activity WHERE pid=pg_backend_pid()')).rows[0].state, 'active');
    const paused = await journal.save(first.client, await source(), job, { ...job.state, phase: 'paused', failure: { code: 503, step: 'account' } }, verify);
    assert.equal(paused.revision, '2');
    await assert.rejects(journal.lock(job.tenantId, job.id), error => error.status === 409);
    const other = await journal.lock(randomUUID(), job.id); await other.release();
    const status = (await pool.query("SELECT state,xact_start FROM pg_stat_activity WHERE pid=$1", [first.client.processID])).rows[0];
    assert.equal(status.state, 'idle'); assert.equal(status.xact_start, null);
  } finally { await first.release(); }
  const next = await journal.lock(job.tenantId, job.id); await next.release();
});

test('real allocator capture, release and completion retain exact actual before/after history and pending DTOs', async () => {
  await allocated(); let job = await capture(await checkpoint(await createJob())); const beforeRelease = structuredClone(job);
  const event = await release(job); assert.equal((await pool.query('SELECT license_company_event_valid(event) AS valid FROM license_company_events event WHERE id=$1', [event.id])).rows[0].valid, true);
  job = await journal.save(database, await source(), job, { ...job.state, items: job.state.items.map(item => ({ ...item, status: 'released', eventId: event.id, poolRevision: event.before_revision })) }, verify);
  job = await journal.save(database, await source(), job, { ...job.state, phase: 'completed_local' }, verify);
  assert.equal(job.revision, '5'); assert.equal(job.state.phase, 'completed_local');
  const history = await journal.history(database, job.tenantId, job.id, { page: 1, limit: 2 }); assert.equal(history.total, 5); assert.equal(history.events.length, 2);
  assert.deepEqual(Object.keys(history.events[0]).sort(), ['id', 'revision', 'phase', 'actorUserId', 'createdAt', 'deliveryStatus', 'failure', 'completedLicenses', 'totalLicenses'].sort());
  assert.deepEqual([history.events[0].completedLicenses, history.events[0].totalLicenses, history.events[0].deliveryStatus], [1, 1, 'pending']);
  const effects = (await pool.query('SELECT * FROM company_offboarding_events WHERE tenant_id=$1 AND workflow_id=$2 ORDER BY revision', [job.tenantId, job.id])).rows;
  assert.equal(effects[0].before_state, null); assert.equal(effects[3].before_state.state.items[0].status, 'pending'); assert.equal(effects[3].after_state.state.items[0].status, 'released');
  assert.equal(effects[3].before_state.state.items[0].assignmentId, beforeRelease.state.items[0].assignmentId);
  assert.ok(effects.every(effect => !Object.hasOwn(effect.authority, 'tokenId') && !JSON.stringify(effect).includes(bearer)));
  fixture.target.enabled = true; fixture.target.eligibilityRevision = '3'; fixture.source.validUntil = 1;
  assert.deepEqual(await journal.load(database, job.tenantId, job.id), job);
});

test('captured identities and membership cannot change; only a real release can advance a captured pool revision', async () => {
  await allocated(); let job = await capture(await checkpoint(await createJob())); const initial = job;
  for (const mutate of [
    state => { state.items = []; }, state => { state.items = null; }, state => { state.items.push({ ...state.items[0] }); },
    state => { state.items[0].name = 'Changed retained metadata'; }, state => { state.items[0].assignmentId = randomUUID(); },
    state => { state.items[0].grantId = randomUUID(); }, state => { state.items[0].poolRevision = '3'; },
    state => { state.items[0].status = 'released'; state.items[0].eventId = randomUUID(); },
    state => { state.phase = 'completed_local'; }, state => { state.checkpoint.afterEligibilityRevision = '3'; },
    state => { state.requestedRevision = '2'; }, state => { state.failure = { code: 503, step: 'account' }; },
  ]) { const state = structuredClone(job.state); mutate(state); await assert.rejects(rawState(job, state)); }
  assert.deepEqual(await journal.load(database, job.tenantId, job.id), initial);
  const product = await companies.get(job.state.items[0].poolId, fixture.user, bearer);
  const anotherUser = randomUUID();
  const originalRead = companies.authority.read.bind(companies.authority);
  companies.authority.read = async (authorization, user, userId = null) => userId === anotherUser ? { ...await originalRead(authorization, user), target: { id: anotherUser, revision: '1', eligibilityRevision: '1', enabled: true, deleted: false } } : originalRead(authorization, user, userId);
  await companies.assign(product.id, { userId: anotherUser, reason: 'Actual unrelated native pool revision advance', confirm: true }, poolEtag(product), fixture.user, bearer);
  const event = await release(job); assert.equal(event.before_revision, '3');
  job = await journal.save(database, await source(), job, { ...job.state, items: [{ ...job.state.items[0], status: 'released', eventId: event.id, poolRevision: event.before_revision }] }, verify);
  await assert.rejects(rawState(job, { ...job.state, items: [{ ...job.state.items[0], status: 'pending', eventId: null }] }));
});

test('foreign, invented, mismatched and incomplete capture evidence fails before any checkpoint is recorded', async () => {
  await allocated(); const job = await checkpoint(await createJob()); const preview = await companies.returnPreview(fixture.userId, {}, fixture.user, bearer);
  const entry = preview.assignments[0]; const item = { poolId: entry.poolId, assignmentId: entry.id, grantId: entry.grantId, poolRevision: entry.poolRevision, name: entry.name, vendor: entry.vendor, status: 'pending', eventId: null };
  for (const change of [{ poolId: randomUUID() }, { assignmentId: randomUUID() }, { grantId: randomUUID() }, { poolRevision: '1' }, { vendor: 'Invented vendor' }, { eventId: randomUUID() }, { extra: 'forbidden' }]) {
    await assert.rejects(rawState(job, { ...job.state, items: [{ ...item, ...change }] }));
  }
  assert.equal((await journal.load(database, job.tenantId, job.id)).state.items, null);
});

test('other workflow release evidence is allowed only as already_released, with exact assignment and retained grant', async () => {
  await allocated(); let job = await capture(await checkpoint(await createJob())); const event = await release(job, randomUUID());
  const item = { ...job.state.items[0], status: 'released', eventId: event.id };
  await assert.rejects(rawState(job, { ...job.state, items: [item] }));
  await assert.rejects(rawState(job, { ...job.state, items: [{ ...item, status: 'already_released', grantId: randomUUID() }] }));
  job = await journal.save(database, await source(), job, { ...job.state, items: [{ ...item, status: 'already_released' }] }, verify);
  assert.equal((await journal.save(database, await source(), job, { ...job.state, phase: 'completed_local' }, verify)).state.phase, 'completed_local');
});

test('eligibility mismatch can pause diagnostically but cannot overwrite the checkpoint, advance or complete', async () => {
  let job = await checkpoint(await createJob(), []); const originalReceipt = structuredClone(job.state.checkpoint); fixture.target.eligibilityRevision = '3';
  await assert.rejects(rawState(job, { ...job.state, phase: 'completed_local' }));
  job = await journal.save(database, await source(), job, { ...job.state, phase: 'paused', failure: { code: 412, step: 'verify' } }, verify);
  assert.deepEqual(job.state.checkpoint, originalReceipt);
  await assert.rejects(rawState(job, { ...job.state, phase: 'licenses', failure: null }));
  await assert.rejects(rawState(job, { ...job.state, checkpoint: { ...originalReceipt, afterEligibilityRevision: '3', beforeEligibilityRevision: '2' } }));
});

test('metadata-only resume can update requestedRevision only before checkpoint and at the original eligibility generation', async () => {
  let job = await createJob(); job = await journal.save(database, await source(), job, { ...job.state, phase: 'paused', failure: { code: 412, step: 'account' } }, verify);
  fixture.target.revision = '2';
  job = await journal.save(database, await source(), job, { ...job.state, phase: 'pending', requestedRevision: '9007199254740993', failure: null }, verify);
  assert.equal(job.state.requestedRevision, '9007199254740993'); assert.equal(job.intent.userRevision, '1');
  fixture.target.eligibilityRevision = '2'; fixture.target.revision = '9007199254740994';
  await assert.rejects(rawState(job, { ...job.state, requestedRevision: fixture.target.revision }));
});

test('completion refuses uncaptured own assignments and performs its own final negative eligibility check', async () => {
  await allocated(); const job = await checkpoint(await createJob(), []);
  await assert.rejects(rawState(job, { ...job.state, phase: 'completed_local' }));
  assert.equal((await pool.query('SELECT count(*)::integer AS count FROM license_assignments')).rows[0].count, 1);
});

test('after-DML rejection and physical source expiry roll back the job, history and mandatory outbox together', async () => {
  const request = intent(); let checks = 0;
  await assert.rejects(journal.create(database, await source(), request, async () => { checks += 1; if (checks === 2) throw Object.assign(new Error('fresh source changed'), { status: 401 }); }), error => error.status === 401);
  assert.equal(await journal.load(database, fixture.source.tenant.id, request.workflowId), null);
  const expired = { ...await source(), validUntil: Math.floor(Date.now() / 1000) + 1 }; checks = 0;
  await assert.rejects(journal.create(database, expired, request, async client => { checks += 1; if (checks === 2) await client.query('SELECT pg_sleep(1.05)'); }), error => [401, 403].includes(error.status));
  assert.equal((await pool.query('SELECT count(*)::integer AS count FROM company_offboarding_events')).rows[0].count, 0);
  assert.equal((await pool.query('SELECT count(*)::integer AS count FROM company_offboarding_outbox')).rows[0].count, 0);
  await assert.rejects(transaction(async client => {
    const shortSource = { ...await source(), validUntil: Math.floor(Date.now() / 1000) + 1 };
    await client.query('SELECT company_offboarding_create($1::jsonb,$2::jsonb)', [shortSource, request]); await client.query('SELECT pg_sleep(1.05)');
  }));
});

test('ready, reads and writes fail closed for disabled or missing mandatory recording receivers', async () => {
  const job = await createJob();
  for (const [relation, trigger] of [['company_offboarding_jobs', 'company_offboarding_guard'], ['company_offboarding_jobs', 'company_offboarding_observe'], ['company_offboarding_events', 'company_offboarding_guard'], ['company_offboarding_events', 'company_offboarding_commit'], ['company_offboarding_outbox', 'company_offboarding_guard']]) {
    await pool.query('ALTER TABLE ' + relation + ' DISABLE TRIGGER ' + trigger);
    try {
      await assert.rejects(journal.ready(), error => error.status === 503);
      await assert.rejects(journal.load(database, job.tenantId, job.id), error => error.status === 503);
      await assert.rejects(journal.save(database, await source(), job, { ...job.state, phase: 'paused', failure: { code: 503, step: 'account' } }, verify), error => error.status === 503);
    } finally { await pool.query('ALTER TABLE ' + relation + ' ENABLE TRIGGER ' + trigger); }
  }
  await pool.query('DROP TRIGGER company_offboarding_observe ON company_offboarding_jobs'); await assert.rejects(journal.ready());
});

test('a suppressing job, history or outbox trigger cannot return a claimed durable write', async () => {
  await pool.query('CREATE FUNCTION journal_test_suppress() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END; $$');
  for (const relation of ['company_offboarding_jobs', 'company_offboarding_events', 'company_offboarding_outbox']) {
    await pool.query('CREATE TRIGGER aaa_test_suppress BEFORE INSERT ON ' + relation + ' FOR EACH ROW EXECUTE FUNCTION journal_test_suppress()');
    const request = intent();
    try { await assert.rejects(journal.create(database, await source(), request, verify), error => error.status === 503); }
    finally { await pool.query('DROP TRIGGER aaa_test_suppress ON ' + relation); }
    assert.equal(await journal.load(database, fixture.source.tenant.id, request.workflowId), null);
  }
});

test('journal evidence is append only and corrupt or missing actual history/outbox cannot be served', async () => {
  const job = await createJob();
  for (const relation of ['company_offboarding_jobs', 'company_offboarding_events', 'company_offboarding_outbox']) {
    await assert.rejects(pool.query('DELETE FROM ' + relation)); await assert.rejects(pool.query('TRUNCATE ' + relation + ' CASCADE'));
  }
  await assert.rejects(pool.query("UPDATE company_offboarding_outbox SET status='pending'"));
  await pool.query('ALTER TABLE company_offboarding_events DISABLE TRIGGER company_offboarding_guard');
  await pool.query("UPDATE company_offboarding_events SET before_state='{}'");
  await pool.query('ALTER TABLE company_offboarding_events ENABLE TRIGGER company_offboarding_guard');
  await assert.rejects(journal.load(database, job.tenantId, job.id), error => error.status === 503);
  await assert.rejects(journal.history(database, job.tenantId, job.id, {}), error => error.status === 503);
});

test('tenant filtered list pagination and history never leak authority or queue internals', async () => {
  const first = await createJob(); await createJob(); await createJob();
  const own = await journal.list(pool, first.tenantId, { page: '2', limit: '2' }); assert.equal(own.total, 3); assert.equal(own.jobs.length, 1); assert.equal(own.limit, 2);
  assert.deepEqual(await journal.list(database, randomUUID(), {}), { jobs: [], total: 0, page: 1, limit: 25 });
  await assert.rejects(journal.history(database, randomUUID(), first.id, {}), error => error.status === 404);
  const history = await journal.history(database, first.tenantId, first.id, {}); assert.equal(history.events[0].totalLicenses, null); assert.equal(history.events[0].completedLicenses, 0);
  for (const field of ['source', 'authority', 'tokenId', 'transaction_id', 'before_state', 'after_state']) assert.ok(!Object.hasOwn(history.events[0], field));
  assert.deepEqual(await journal.list(database, first.tenantId, { page: 3, limit: 2 }), { jobs: [], total: 3, page: 3, limit: 2 });
});

test('account receipt shape, operation and original Identity revisions fail closed while global sequence jumps are retained', async () => {
  const job = await createJob(); const identity = receipt(job); fixture.target.enabled = false; fixture.target.revision = identity.afterRevision; fixture.target.eligibilityRevision = identity.afterEligibilityRevision;
  for (const change of [{ createdAt: undefined, createdAtISO: identity.createdAt }, { workflowId: randomUUID() }, { tenantId: randomUUID() }, { userId: randomUUID() },
    { actorUserId: randomUUID() }, { operationId: null }, { beforeRevision: '2' }, { afterRevision: '1' }, { afterEligibilityRevision: '1' }, { deliveryStatus: 'delivered' }, { createdAt: '2026-02-31T00:00:00.000Z' }]) {
    await assert.rejects(journal.save(database, await source(), job, { ...job.state, phase: 'licenses', checkpoint: { ...identity, ...change } }, verify), error => error.status === 409);
  }
  const checkpointed = await journal.save(database, await source(), job, { ...job.state, phase: 'licenses', checkpoint: identity }, verify);
  assert.equal(checkpointed.state.checkpoint.afterRevision, '80'); assert.equal(checkpointed.state.checkpoint.afterEligibilityRevision, '84');
});

test('already-disabled receipts have equal revisions and a null operation, with no invented account mutation', async () => {
  fixture.target.enabled = false; let job = await createJob();
  const identity = { ...receipt(job), action: 'already_disabled', operationId: null, afterRevision: job.state.requestedRevision, afterEligibilityRevision: job.intent.eligibilityRevision };
  job = await journal.save(database, await source(), job, { ...job.state, phase: 'licenses', checkpoint: identity, items: [] }, verify);
  assert.equal((await journal.save(database, await source(), job, { ...job.state, phase: 'completed_local' }, verify)).state.phase, 'completed_local');
});

test('paused eligibility diagnostics cannot capture, clear, remove or advance items even when an actual release exists', async () => {
  await allocated(); let job = await capture(await checkpoint(await createJob())); const event = await release(job); fixture.target.eligibilityRevision = '9007199254740993';
  const diagnostic = { ...job.state, phase: 'paused', failure: { code: 409, step: 'verify' } };
  for (const items of [null, [], [{ ...job.state.items[0], status: 'released', eventId: event.id, poolRevision: event.before_revision }]]) await assert.rejects(rawState(job, { ...diagnostic, items }));
  job = await journal.save(database, await source(), job, diagnostic, verify); assert.equal(job.state.items[0].status, 'pending');
  assert.deepEqual(job.state.failure, { code: 409, step: 'verify' });
});

test('a committed child release can be recovered after a parent save outage without changing pending versions or replaying the child', async () => {
  await allocated(); let job = await capture(await checkpoint(await createJob())); const event = await release(job);
  let checks = 0;
  await assert.rejects(journal.save(database, await source(), job, { ...job.state, items: [{ ...job.state.items[0], status: 'released', eventId: event.id, poolRevision: event.before_revision }] }, async () => { checks += 1; if (checks === 2) throw new Error('explicit parent acknowledgement outage'); }));
  job = await journal.load(database, job.tenantId, job.id); assert.equal(job.state.items[0].status, 'pending');
  job = await journal.save(database, await source(), job, { ...job.state, phase: 'paused', failure: { code: 503, step: 'licenses' } }, verify);
  job = await journal.save(database, await source(), job, { ...job.state, phase: 'licenses', failure: null, items: [{ ...job.state.items[0], status: 'released', eventId: event.id, poolRevision: event.before_revision }] }, verify);
  assert.equal(job.state.items[0].eventId, event.id);
  assert.equal((await pool.query("SELECT count(*)::integer AS count FROM license_company_events WHERE type='app.license.released'")).rows[0].count, 1);
});

test('immutable intent, tenant, workflow, creator, exact revision increments and stale saves are guarded in SQL', async () => {
  const job = await createJob(); const paused = { ...job.state, phase: 'paused', failure: { code: 503, step: 'account' } };
  for (const change of [",intent=jsonb_set(intent,'{reason}','\"Changed immutable offboarding reason\"')", ',tenant_id=gen_random_uuid()', ',id=gen_random_uuid()', ',created_by=gen_random_uuid()', ',user_id=gen_random_uuid()']) await assert.rejects(rawState(job, paused, change));
  await assert.rejects(transaction(async client => {
    await client.query("SELECT set_config('opendirectory.company_offboarding_source',$1,true)", [JSON.stringify(await source())]);
    await client.query('UPDATE company_offboarding_jobs SET state=$1,revision=revision+2 WHERE tenant_id=$2 AND id=$3', [paused, job.tenantId, job.id]);
  }));
  const current = await journal.save(database, await source(), job, paused, verify);
  await assert.rejects(journal.save(database, await source(), job, paused, verify), error => error.status === 409);
  assert.equal(current.revision, '2'); assert.equal((await journal.history(database, job.tenantId, job.id, {})).total, 2);
});

test('ready verifies mandatory schema constraints and column types, and rejects suppressed origin trigger execution', async () => {
  for (const alteration of ["ALTER TABLE company_offboarding_outbox DROP CONSTRAINT company_offboarding_outbox_status_check", 'ALTER TABLE company_offboarding_outbox ALTER COLUMN tenant_id DROP NOT NULL', 'ALTER TABLE company_offboarding_events DROP CONSTRAINT company_offboarding_events_transaction_id_key', "SET LOCAL session_replication_role='replica'"]) {
    await transaction(async client => {
      await client.query(alteration); await assert.rejects(journal.ready(client), error => error.status === 503);
      await client.query('ROLLBACK'); await client.query('BEGIN');
    });
  }
  await journal.ready();
});

test('reads revalidate retained child release evidence and mandatory journal outbox after owner-side trace corruption', async () => {
  await allocated(); let job = await capture(await checkpoint(await createJob())); const event = await release(job);
  job = await journal.save(database, await source(), job, { ...job.state, items: [{ ...job.state.items[0], status: 'released', eventId: event.id }] }, verify);
  for (const relation of ['license_company_outbox', 'company_offboarding_outbox']) {
    await transaction(async client => {
      await client.query('ALTER TABLE ' + relation + ' DISABLE TRIGGER USER');
      await client.query(relation === 'license_company_outbox' ? 'DELETE FROM license_company_outbox WHERE id=$1' : 'DELETE FROM company_offboarding_outbox WHERE id=(SELECT id FROM company_offboarding_events WHERE workflow_id=$1 ORDER BY revision DESC LIMIT 1)', [relation === 'license_company_outbox' ? event.id : job.id]);
      await client.query('ALTER TABLE ' + relation + ' ENABLE TRIGGER USER');
      await assert.rejects(journal.load(client, job.tenantId, job.id), error => error.status === 503);
      await client.query('ROLLBACK'); await client.query('BEGIN');
    });
  }
  assert.equal((await journal.load(database, job.tenantId, job.id)).revision, job.revision);
});

test('SQL checks original request source structure and refuses allocator transaction mixing and changed commit authority', async () => {
  const request = intent(); const original = await source();
  for (const change of [{ permissions: ['company.apps.read'] }, { extra: true }, { target: { ...original.target, extra: true } }, { context: { ...original.context, rolesRevision: 123 } }, { validUntil: 1 }]) {
    await assert.rejects(transaction(client => client.query('SELECT company_offboarding_create($1::jsonb,$2::jsonb)', [{ ...original, ...change }, request])));
  }
  await assert.rejects(transaction(async client => {
    await client.query("SELECT set_config('opendirectory.license_company',$1,true)", [randomUUID()]);
    await client.query('SELECT company_offboarding_create($1::jsonb,$2::jsonb)', [original, request]);
  }));
  await assert.rejects(transaction(async client => {
    await client.query('SELECT company_offboarding_create($1::jsonb,$2::jsonb)', [original, request]);
    await client.query("SELECT set_config('opendirectory.company_offboarding_source',$1,true)", [JSON.stringify({ ...original, issuer: 'https://changed-request.fixture' })]);
  }));
  assert.equal(await journal.load(database, fixture.source.tenant.id, request.workflowId), null);
});

test('directory record intent and checkpoint revisions remain independent of authorization target revision', async () => {
  fixture.target.revision = '1'; let job = await createJob(intent({ userRevision: '41' }));
  assert.equal(job.intent.userRevision, '41'); assert.equal((await source()).target.revision, '1');
  const identity = receipt(job); fixture.target.enabled = false; fixture.target.revision = '2'; fixture.target.eligibilityRevision = identity.afterEligibilityRevision;
  job = await journal.save(database, await source(), job, { ...job.state, phase: 'licenses', checkpoint: identity, items: [] }, verify);
  assert.equal(job.state.checkpoint.beforeRevision, '41'); assert.equal(job.state.checkpoint.afterRevision, '120');
  assert.equal((await journal.save(database, await source(), job, { ...job.state, phase: 'completed_local' }, verify)).state.phase, 'completed_local');
});

test('a fabricated completed trace cannot remove captured pending membership after journal guards are restored', async () => {
  await allocated(); let job = await capture(await checkpoint(await createJob()));
  job = await journal.save(database, await source(), job, { ...job.state, phase: 'paused', failure: { code: 503, step: 'licenses' } }, verify);
  await transaction(async client => {
    await client.query('ALTER TABLE company_offboarding_jobs DISABLE TRIGGER USER'); await client.query('ALTER TABLE company_offboarding_events DISABLE TRIGGER USER');
    await client.query("UPDATE company_offboarding_jobs SET state=jsonb_set(jsonb_set(jsonb_set(state,'{items}','[]'),'{phase}','\"completed_local\"'),'{failure}','null') WHERE tenant_id=$1 AND id=$2", [job.tenantId, job.id]);
    await client.query('UPDATE company_offboarding_events SET after_state=(SELECT to_jsonb(job) FROM company_offboarding_jobs job WHERE tenant_id=$1 AND id=$2) WHERE tenant_id=$1 AND workflow_id=$2 AND revision=$3', [job.tenantId, job.id, job.revision]);
    await client.query('ALTER TABLE company_offboarding_jobs ENABLE TRIGGER USER'); await client.query('ALTER TABLE company_offboarding_events ENABLE TRIGGER USER');
    await assert.rejects(journal.load(client, job.tenantId, job.id), error => error.status === 503);
    await client.query('ROLLBACK'); await client.query('BEGIN');
  });
  assert.equal((await journal.load(database, job.tenantId, job.id)).state.items.length, 1);
});
