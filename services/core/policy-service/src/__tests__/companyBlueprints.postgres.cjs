'use strict';

const { test, beforeEach, afterEach, after } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { Pool } = require('pg');
const { CompanyBlueprints } = require('../CompanyBlueprints');
const { CompanyLicenses } = require('../licenses/CompanyLicenses');
const { LicenseAllocator } = require('../licenses/LicenseAllocator');
const { COMPANY_BLUEPRINT_PERMISSIONS, etag } = require('../../../../../packages/company-blueprint-contract');
const { COMPANY_LICENSE_PERMISSIONS } = require('../../../../../packages/company-license-contract');

const administration = new Pool({ connectionString: process.env.LICENSE_TEST_DATABASE_URL, max: 1 });
const bearer = 'Bearer company.blueprint.native';
const reason = 'Explicitly reviewed own local desired configuration';
let schema; let pool; let store; let database; let state; let companies;
function draft(changes = {}) { return { name: 'Own blueprint', description: '', platform: 'all', configurations: [configuration()], appPoolIds: [], ...changes }; }
function configuration(minutes = 5, changes = {}) { return { id: randomUUID(), type: 'screen_lock', name: 'Desired screen lock', payloadJson: JSON.stringify({ minutes, requirePassword: true }), ...changes }; }
function request(action = 'created', id = randomUUID(), revision = '0', changes = {}) { return { id: randomUUID(), correlationId: randomUUID(), blueprintId: id, action, expectedRevision: revision, reason, draft: action === 'created' || action === 'updated' ? draft() : null, version: null, ...changes }; }
function change(action, id, body, revision, operation = randomUUID()) { return store.change(action, id, { ...body, reason, confirm: true }, revision ? etag({ id, revision }) : undefined, operation, state.user, bearer); }
function create(document = draft(), id = randomUUID(), operation = randomUUID()) { return change('created', id, { id, draft: document }, null, operation); }
async function raw(command, source = state.source, applicationSource = null) { return (await pool.query('SELECT company_blueprint_change($1::jsonb,$2::jsonb,$3::jsonb) AS result', [source, applicationSource, command])).rows[0].result; }
async function snapshots() {
  const result = {};
  for (const relation of ['license_catalog', 'license_subjects', 'license_assignments', 'license_assignment_sources', 'license_grants', 'license_grant_events', 'license_audit_events', 'license_company_commands', 'license_company_events', 'license_company_outbox']) result[relation] = (await pool.query('SELECT to_jsonb(actual) AS value FROM ' + relation + ' actual ORDER BY to_jsonb(actual)::text')).rows;
  return result;
}
beforeEach(async () => {
  schema = 'company_blueprint_' + randomUUID().replaceAll('-', ''); await administration.query('CREATE SCHEMA ' + schema);
  const url = new URL(process.env.LICENSE_TEST_DATABASE_URL); url.searchParams.set('options', '-c search_path=' + schema + ',public -c timezone=UTC'); pool = new Pool({ connectionString: url.toString(), max: 8 });
  const directory = path.join(__dirname, '../db/migrations');
  for (const filename of fs.readdirSync(directory).filter(filename => filename.endsWith('.sql')).sort()) await pool.query(fs.readFileSync(path.join(directory, filename), 'utf8'));
  const now = Math.floor(Date.now() / 1000); const userId = randomUUID();
  const user = { actor_type: 'user', token_use: 'access', iss: 'https://company-blueprints.native', sub: 'actual-owner', jti: randomUUID(), exp: now + 3600, auth_time: now,
    identity_authorization: { userId, revision: '1', linkRevision: '1', rolesRevision: 'a'.repeat(64) }, amr: ['pwd', 'otp'], mfa_authorization: { schemaVersion: 1, userId, revision: '1', authTime: now, methods: ['pwd', 'otp'] } };
  const source = { schemaVersion: 1, companyBlueprintProtocol: 1, issuer: user.iss, subject: user.sub, tokenId: user.jti, expiresAt: user.exp, context: user.identity_authorization,
    tenant: { id: randomUUID(), version: '1', generation: '1' }, actorUserId: userId, permissions: [...COMPANY_BLUEPRINT_PERMISSIONS], validUntil: now + 300 };
  const { companyBlueprintProtocol, ...base } = structuredClone(source); const applicationSource = { ...base, permissions: [...COMPANY_LICENSE_PERMISSIONS], target: null };
  state = { user, source, applicationSource, checks: 0, appChecks: 0, hook: null, appHook: null, queryHook: null, targets: new Map() };
  database = { query: (...args) => pool.query(...args), getClient: async () => {
    const client = await pool.connect(); return { query: async (...args) => { if (state.queryHook) await state.queryHook(client, ...args); return client.query(...args); }, release: () => client.release() };
  } };
  const authority = { read: async () => { state.checks++; if (state.hook) await state.hook(state.checks); return structuredClone(state.source); } };
  const applicationAuthority = { read: async (_authorization, _user, userId = null) => {
    state.appChecks++; if (state.appHook) await state.appHook(state.appChecks);
    if (userId !== null && !state.targets.has(userId)) throw Object.assign(new Error('Unknown own employee fixture'), { status: 404 });
    return structuredClone(userId === null ? state.applicationSource : { ...state.applicationSource, target: state.targets.get(userId) });
  } };
  store = new CompanyBlueprints(database, { authority, applicationAuthority }); companies = new CompanyLicenses(new LicenseAllocator(database), { authority: applicationAuthority });
});
afterEach(async () => { await pool.end(); await administration.query('DROP SCHEMA IF EXISTS ' + schema + ' CASCADE'); });
after(async () => administration.end());

test('real own draft, immutable release, restore and republish preserve independent head and full metadata history', async () => {
  const original = draft({ configurations: [configuration()] }); const created = await create(original); assert.equal(created.revision, '1'); assert.equal(created.publishedVersion, null);
  const first = await change('published', created.blueprintId, {}, '1'); assert.equal(first.revision, '2'); assert.equal(first.publishedVersion, 1);
  const updated = await change('updated', created.blueprintId, { draft: draft({ name: 'Changed', configurations: [configuration(10)] }) }, '2'); assert.equal(updated.revision, '3');
  const second = await change('published', created.blueprintId, {}, '3'); assert.equal(second.publishedVersion, 2);
  const restored = await change('restored', created.blueprintId, { version: 1 }, '4'); assert.equal(restored.revision, '5'); assert.equal(restored.publishedVersion, 2);
  const detail = await store.get(created.blueprintId, state.user, bearer); assert.equal(detail.blueprint.draftChanged, true); assert.equal(detail.blueprint.draft.name, original.name);
  const third = await change('published', created.blueprintId, {}, '5'); assert.equal(third.publishedVersion, 3);
  const releases = await store.versions(created.blueprintId, {}, state.user, bearer); assert.deepEqual(releases.versions.map(item => item.version), [3, 2, 1]);
  const historical = await store.version(created.blueprintId, '1', state.user, bearer); assert.equal(historical.version.draft.name, original.name); assert.equal(historical.version.sourceRevision, '1');
  const history = await store.history(created.blueprintId, {}, state.user, bearer); assert.equal(history.total, 6); assert.equal(history.events[1].restoredFrom, 1); assert.ok(history.events.every(event => event.version === 1 && event.deliveryStatus === 'pending' && !Object.hasOwn(event, 'draft')));
});
test('lost acknowledgement returns historical receipt before stale ETag without overwriting newer draft or release', async () => {
  const id = randomUUID(); const operation = randomUUID(); const document = draft(); const created = await create(document, id, operation);
  const published = await change('published', id, {}, '1'); await change('updated', id, { draft: draft({ name: 'Newer draft' }) }, '2');
  state.source.tokenId = randomUUID(); state.source.context.revision = '4'; state.source.validUntil = Math.floor(Date.now() / 1000) + 299;
  const recovered = await create(document, id, operation); assert.equal(recovered.outcome, 'already_applied'); assert.equal(recovered.revision, created.revision); assert.equal(recovered.publishedVersion, null);
  assert.equal((await store.get(id, state.user, bearer)).blueprint.draft.name, 'Newer draft'); assert.equal((await store.versions(id, {}, state.user, bearer)).total, published.publishedVersion);
  assert.equal((await store.history(id, {}, state.user, bearer)).total, 3);
});
test('same operation with changed intent or another actor, tenant or issuer is rejected without writes', async () => {
  const id = randomUUID(); const operation = randomUUID(); await create(draft(), id, operation);
  for (const mutation of ['draft', 'actor', 'tenant', 'issuer', 'subject']) {
    const original = structuredClone(state.source);
    if (mutation === 'actor') { state.source.actorUserId = randomUUID(); state.source.context.userId = state.source.actorUserId; }
    if (mutation === 'tenant') state.source.tenant.id = randomUUID(); if (mutation === 'issuer') state.source.issuer += '/changed'; if (mutation === 'subject') state.source.subject += '-changed';
    await assert.rejects(create(mutation === 'draft' ? draft({ name: 'different' }) : draft(), id, operation), { status: 409 }); state.source = original;
  }
  assert.equal((await store.history(id, {}, state.user, bearer)).total, 1);
});
test('own tenant isolation covers list, detail, releases, history and every mutation', async () => {
  const created = await create(); const own = state.source.tenant.id; state.source.tenant.id = randomUUID(); assert.equal((await store.list({}, state.user, bearer)).total, 0);
  for (const operation of [() => store.get(created.blueprintId, state.user, bearer), () => store.versions(created.blueprintId, {}, state.user, bearer), () => store.version(created.blueprintId, 1, state.user, bearer), () => store.history(created.blueprintId, {}, state.user, bearer), () => change('updated', created.blueprintId, { draft: draft({ name: 'foreign' }) }, '1'), () => change('published', created.blueprintId, {}, '1'), () => change('restored', created.blueprintId, { version: 1 }, '1')]) await assert.rejects(operation(), { status: 404 });
  state.source.tenant.id = own; assert.equal((await store.get(created.blueprintId, state.user, bearer)).blueprint.revision, '1');
});
test('JSONB equality deduplicates equal payloads and blocks internal conflicting releases without writes', async () => {
  const first = configuration(); const equal = configuration(5, { payloadJson: '{"requirePassword":true,"minutes":5}' }); const created = await create(draft({ configurations: [first, equal] }));
  const preview = (await store.get(created.blueprintId, state.user, bearer)).blueprint.preview; assert.equal(preview.effectiveConfigurations.length, 1); assert.equal(preview.effectiveConfigurations[0].sources.length, 2);
  const updated = await change('updated', created.blueprintId, { draft: draft({ configurations: [first, configuration(10)] }) }, '1');
  assert.equal((await store.get(created.blueprintId, state.user, bearer)).blueprint.preview.hasConflicts, true);
  await assert.rejects(change('published', created.blueprintId, {}, updated.revision), { status: 409 }); assert.equal((await store.history(created.blueprintId, {}, state.user, bearer)).total, 2);
});
test('unchanged saves, restores and releases cannot manufacture revisions or repeated published versions', async () => {
  const document = draft(); const created = await create(document); await assert.rejects(change('updated', created.blueprintId, { draft: document }, '1'), { status: 409 });
  await change('published', created.blueprintId, {}, '1'); await assert.rejects(change('published', created.blueprintId, {}, '2'), { status: 409 });
  await assert.rejects(change('restored', created.blueprintId, { version: 1 }, '2'), { status: 409 }); assert.equal((await store.history(created.blueprintId, {}, state.user, bearer)).total, 2);
});
test('independent own finite app references snapshot only catalog metadata without allocating or changing stock', async () => {
  const product = await companies.create({ name: 'Own native app', vendor: 'Native vendor', description: '', totalSeats: 2, reason }, state.user, bearer);
  const before = await snapshots(); const created = await create(draft({ appPoolIds: [product.id] })); await change('published', created.blueprintId, {}, '1');
  const released = await store.version(created.blueprintId, 1, state.user, bearer); assert.deepEqual(released.version.apps, [{ id: product.id, name: product.name, vendor: product.vendor, revision: product.revision }]); assert.deepEqual(await snapshots(), before);
  assert.ok(state.appChecks > 0); assert.equal((await pool.query('SELECT count(*)::int AS count FROM license_assignments')).rows[0].count, 0);
});
test('historical app metadata stays readable after legitimate catalog revision changes and replay needs no app source', async () => {
  const product = await companies.create({ name: 'Native app', vendor: 'Vendor', description: '', totalSeats: 2, reason }, state.user, bearer);
  const id = randomUUID(); const operation = randomUUID(); const document = draft({ appPoolIds: [product.id] }); await create(document, id, operation); await change('published', id, {}, '1');
  await companies.update(product.id, { name: 'Renamed app', vendor: product.vendor, description: '', totalSeats: 3, reason, confirm: true }, require('../../../../../packages/company-license-contract').poolEtag(product), state.user, bearer);
  state.appHook = async () => { throw Object.assign(new Error('No current independent app privilege'), { status: 403 }); };
  const historical = await store.version(id, 1, state.user, bearer); assert.equal(historical.version.apps[0].name, 'Native app'); assert.equal(historical.version.apps[0].revision, '1');
  assert.equal((await create(document, id, operation)).outcome, 'already_applied'); await assert.rejects(change('updated', id, { draft: { ...document, name: 'Needs app authority' } }, '2'), { status: 403 });
});
test('no app references require no app source while mismatched actor or tenant app source fails closed', async () => {
  await create(); assert.equal(state.appChecks, 0);
  for (const field of ['tenant', 'actor', 'context', 'target']) {
    const original = structuredClone(state.applicationSource); if (field === 'tenant') state.applicationSource.tenant.id = randomUUID(); if (field === 'actor') state.applicationSource.actorUserId = randomUUID(); if (field === 'context') state.applicationSource.context.revision = '99'; if (field === 'target') state.applicationSource.target = { id: randomUUID() };
    await assert.rejects(create(draft({ appPoolIds: [randomUUID()] })), { status: 401 }); state.applicationSource = original;
  }
});
test('foreign, missing and unowned legacy application pools are never admitted as own desired apps', async () => {
  const product = await companies.create({ name: 'App', vendor: 'Vendor', description: '', totalSeats: 2, reason }, state.user, bearer);
  const tenant = state.source.tenant.id; state.source.tenant.id = randomUUID(); state.applicationSource.tenant.id = state.source.tenant.id;
  await assert.rejects(create(draft({ appPoolIds: [product.id] })), { status: 404 }); state.source.tenant.id = tenant; state.applicationSource.tenant.id = tenant;
  await assert.rejects(create(draft({ appPoolIds: [randomUUID()] })), { status: 404 });
  const legacy = (await pool.query("INSERT INTO license_catalog(name,vendor,total_seats) VALUES('Legacy','Vendor',2) RETURNING id")).rows[0];
  await assert.rejects(create(draft({ appPoolIds: [legacy.id] })), { status: 404 });
});
test('parallel stale writers produce one winner and retain complete head revision chain', async () => {
  const created = await create(); const results = await Promise.allSettled([change('updated', created.blueprintId, { draft: draft({ name: 'First' }) }, '1'), change('updated', created.blueprintId, { draft: draft({ name: 'Second' }) }, '1')]);
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 1); assert.equal(results.find(result => result.status === 'rejected').reason.status, 412); assert.equal((await store.history(created.blueprintId, {}, state.user, bearer)).total, 2);
});
test('authority withdrawn after DML rolls back head, private intent, events, releases and outbox', async () => {
  state.hook = async count => { if (count === 3) throw Object.assign(new Error('Original identity withdrawn'), { status: 401 }); };
  await assert.rejects(create(), { status: 401 }); for (const relation of ['company_blueprints', 'company_blueprint_operations', 'company_blueprint_versions', 'company_blueprint_events', 'company_blueprint_outbox']) assert.equal((await pool.query('SELECT count(*)::int AS count FROM ' + relation)).rows[0].count, 0);
});
test('actual deferred clock rejects a source expiring after DML and the last issuer read', async () => {
  await pool.query('CREATE TABLE test_blueprint_clock(seconds integer);INSERT INTO test_blueprint_clock VALUES(0)'); await pool.query("CREATE OR REPLACE FUNCTION company_blueprint_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+seconds*interval '1 second' FROM test_blueprint_clock; $$");
  state.hook = async count => { if (count === 3) await pool.query('UPDATE test_blueprint_clock SET seconds=301'); };
  await assert.rejects(create(), { status: 503 }); assert.equal((await pool.query('SELECT count(*)::int AS count FROM company_blueprints')).rows[0].count, 0);
});
test('independent app deadline also remains binding at deferred commit', async () => {
  const product = await companies.create({ name: 'App', vendor: 'Vendor', description: '', totalSeats: 2, reason }, state.user, bearer); state.checks = 0;
  state.applicationSource.validUntil = Math.floor(Date.now() / 1000) + 100;
  await pool.query('CREATE TABLE test_blueprint_clock(seconds integer);INSERT INTO test_blueprint_clock VALUES(0)'); await pool.query("CREATE OR REPLACE FUNCTION company_blueprint_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+seconds*interval '1 second' FROM test_blueprint_clock; $$");
  state.hook = async count => { if (count === 3) await pool.query('UPDATE test_blueprint_clock SET seconds=101'); };
  await assert.rejects(create(draft({ appPoolIds: [product.id] })), { status: 503 }); assert.equal((await pool.query('SELECT count(*)::int AS count FROM company_blueprints')).rows[0].count, 0);
});
test('raw SQL cannot mutate or erase retained head, releases, intent, history or outbox outside an original command', async () => {
  const created = await create(); await change('published', created.blueprintId, {}, '1');
  for (const relation of ['company_blueprints', 'company_blueprint_operations', 'company_blueprint_versions', 'company_blueprint_events', 'company_blueprint_outbox']) {
    await assert.rejects(pool.query('DELETE FROM ' + relation), error => error.code === '42501'); await assert.rejects(pool.query('TRUNCATE ' + relation + ' CASCADE'), error => error.code === '42501');
  }
  await assert.rejects(pool.query("UPDATE company_blueprints SET revision=99"), error => error.code === '42501'); await assert.rejects(pool.query("UPDATE company_blueprint_versions SET draft='{}'::jsonb"), error => error.code === '42501');
});
test('receiving detects a missing guard and missing immutable event even after owner tampering', async () => {
  const created = await create(); await pool.query('ALTER TABLE company_blueprints DISABLE TRIGGER company_blueprints_guard'); await assert.rejects(store.get(created.blueprintId, state.user, bearer), { status: 503 }); await pool.query('ALTER TABLE company_blueprints ENABLE TRIGGER company_blueprints_guard');
  await pool.query('ALTER TABLE company_blueprint_events DISABLE TRIGGER ALL;ALTER TABLE company_blueprint_outbox DISABLE TRIGGER ALL'); await pool.query('DELETE FROM company_blueprint_outbox;DELETE FROM company_blueprint_events'); await pool.query('ALTER TABLE company_blueprint_events ENABLE TRIGGER ALL;ALTER TABLE company_blueprint_outbox ENABLE TRIGGER ALL');
  await assert.rejects(store.capabilities(state.user, bearer), { status: 503 });
});
test('migration replay preserves all drafts, immutable releases, historical receipts and pending outbox', async () => {
  const created = await create(); await change('published', created.blueprintId, {}, '1'); const history = await store.history(created.blueprintId, {}, state.user, bearer);
  await pool.query(fs.readFileSync(path.join(__dirname, '../db/migrations/025_company_blueprints.sql'), 'utf8')); assert.deepEqual(await store.history(created.blueprintId, {}, state.user, bearer), history); assert.equal((await store.version(created.blueprintId, 1, state.user, bearer)).version.version, 1);
});
for (const [name, transform] of [
  ['decimal precision', document => { document.configurations[0].payloadJson = '{"minutes":5.00000000000000001,"requirePassword":true}'; }],
  ['decimal literal', document => { document.configurations[0].payloadJson = '{"minutes":5.0,"requirePassword":true}'; }],
  ['exponent literal', document => { document.configurations[0].payloadJson = '{"minutes":5e0,"requirePassword":true}'; }],
  ['duplicate key', document => { document.configurations[0].payloadJson = '{"minutes":5,"minutes":10,"requirePassword":true}'; }],
  ['escaped duplicate', document => { document.configurations[0].payloadJson = '{"minutes":5,"\\u006dinutes":10,"requirePassword":true}'; }],
  ['secret property', document => { document.configurations[0].payloadJson = '{"minutes":5,"requirePassword":true,"password":"secret"}'; }],
  ['unsupported wifi', document => { document.configurations[0].type = 'wifi'; }],
  ['arbitrary nested data', document => { document.configurations[0].payloadJson = '{"minutes":5,"requirePassword":{"secret":"value"}}'; }],
  ['configuration count', document => { document.configurations = Array.from({ length: 26 }, () => configuration()); }],
  ['duplicate configuration ID', document => { document.configurations.push({ ...document.configurations[0] }); }],
  ['duplicate application', document => { const id = randomUUID(); document.appPoolIds = [id, id]; }],
  ['oversized payload', document => { document.configurations[0].payloadJson = ' '.repeat(65537); }],
]) test('SQL independently rejects ' + name + ' before any retained effects', async () => {
  const document = draft({ configurations: [configuration()] }); transform(document); const command = request('created', randomUUID(), '0', { draft: document });
  assert.equal((await pool.query('SELECT company_blueprint_draft_valid($1::jsonb) AS valid', [document])).rows[0].valid, false); await assert.rejects(raw(command), error => error.code === '42501'); assert.equal((await pool.query('SELECT count(*)::int AS count FROM company_blueprints')).rows[0].count, 0);
});
test('bounded list, releases and history use real page totals and exact query shape', async () => {
  for (let index = 0; index < 3; index++) await create(draft({ name: 'Search ' + index })); assert.equal((await store.list({ search: 'Search' }, state.user, bearer)).total, 3); assert.equal((await store.list({ page: '2' }, state.user, bearer)).blueprints.length, 0);
  await assert.rejects(store.list({ tenantId: randomUUID() }, state.user, bearer), { status: 400 });
});
test('empty drafts are authorable but empty releases never create meaningless applied artifacts', async () => {
  const created = await create(draft({ configurations: [] })); await assert.rejects(change('published', created.blueprintId, {}, '1'), { status: 409, message: 'company_blueprint_empty' });
  assert.equal((await store.versions(created.blueprintId, {}, state.user, bearer)).total, 0); assert.equal((await store.history(created.blueprintId, {}, state.user, bearer)).total, 1);
});
test('apps-only local releases are supported without pretending configuration deployment or license allocation', async () => {
  const product = await companies.create({ name: 'App', vendor: 'Vendor', description: '', totalSeats: 2, reason }, state.user, bearer);
  const created = await create(draft({ configurations: [], appPoolIds: [product.id] })); await change('published', created.blueprintId, {}, '1');
  const released = await store.version(created.blueprintId, 1, state.user, bearer); assert.equal(released.version.draft.configurations.length, 0); assert.equal(released.version.apps.length, 1); assert.equal((await pool.query('SELECT count(*)::int AS count FROM license_assignments')).rows[0].count, 0);
});
test('publish and restore lost ACK receipts recover exact old results without touching newer drafts or released head', async () => {
  const created = await create(); const publishOperation = randomUUID(); const published = await change('published', created.blueprintId, {}, '1', publishOperation);
  await change('updated', created.blueprintId, { draft: draft({ name: 'Second release' }) }, '2'); await change('published', created.blueprintId, {}, '3');
  const restoreOperation = randomUUID(); const restored = await change('restored', created.blueprintId, { version: 1 }, '4', restoreOperation);
  await change('updated', created.blueprintId, { draft: draft({ name: 'Newest draft' }) }, '5');
  assert.deepEqual(await change('published', created.blueprintId, {}, '1', publishOperation), { ...published, outcome: 'already_applied' });
  assert.deepEqual(await change('restored', created.blueprintId, { version: 1 }, '4', restoreOperation), { ...restored, outcome: 'already_applied' });
  const current = await store.get(created.blueprintId, state.user, bearer); assert.equal(current.blueprint.revision, '6'); assert.equal(current.blueprint.publishedVersion, 2); assert.equal(current.blueprint.draft.name, 'Newest draft');
  await assert.rejects(change('restored', created.blueprintId, { version: 2 }, '4', restoreOperation), { status: 409 });
});
test('an expired original historical source does not prevent an effect-free receipt under new current authority', async () => {
  await pool.query('CREATE TABLE test_blueprint_clock(seconds integer);INSERT INTO test_blueprint_clock VALUES(0)'); await pool.query("CREATE OR REPLACE FUNCTION company_blueprint_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+seconds*interval '1 second' FROM test_blueprint_clock; $$");
  const id = randomUUID(); const operation = randomUUID(); const document = draft(); const command = request('created', id, '0', { id: operation, draft: document }); const original = await raw(command);
  await pool.query('UPDATE test_blueprint_clock SET seconds=301'); const current = { ...state.source, tokenId: randomUUID(), validUntil: Math.floor(Date.now() / 1000) + 600, expiresAt: state.source.expiresAt };
  assert.equal((await raw({ ...command, correlationId: randomUUID() }, current)).outcome, 'already_applied'); assert.equal((await pool.query('SELECT revision::text FROM company_blueprints WHERE id=$1', [id])).rows[0].revision, original.revision);
});
test('SQL independently rejects C1 controls, untrimmed unicode text and noncanonical source identifiers', async () => {
  for (const name of ['Own\u0085name', '\u00a0Own', 'Own\u2009']) assert.equal((await pool.query('SELECT company_blueprint_draft_valid($1::jsonb) AS valid', [draft({ name })])).rows[0].valid, false);
  const proof = { ...state.source, actorUserId: state.source.actorUserId.toUpperCase() }; await assert.rejects(raw(request(), proof), error => error.code === '42501');
});
test('receiving detects replaced validators and disabled deferred guards rather than trusting a green capability', async () => {
  const created = await create(); await pool.query('ALTER TABLE company_blueprint_operations DISABLE TRIGGER company_blueprint_operations_commit'); await assert.rejects(store.capabilities(state.user, bearer), { status: 503 });
  await pool.query('ALTER TABLE company_blueprint_operations ENABLE TRIGGER company_blueprint_operations_commit');
  await pool.query('CREATE OR REPLACE FUNCTION company_blueprint_source_valid(source jsonb,live boolean DEFAULT true) RETURNS boolean LANGUAGE sql VOLATILE AS $$ SELECT true; $$');
  await assert.rejects(store.get(created.blueprintId, state.user, bearer), { status: 503 }); await assert.rejects(create(), { status: 503 });
});
test('all three typed desired schemas survive exact persisted SQL payloads without provider validation claims', async () => {
  const created = await create(draft({ configurations: [configuration(), configuration(5, { type: 'filevault', payloadJson: '{"enabled":true}' }), configuration(5, { type: 'software_update', payloadJson: '{"automatic":false,"deferralDays":365}' })] }));
  await change('published', created.blueprintId, {}, '1'); const preview = (await store.get(created.blueprintId, state.user, bearer)).blueprint.preview; assert.equal(preview.effectiveConfigurations.length, 3); assert.equal(preview.hasConflicts, false);
});
test('normal existing allocator assignment advances app pool revision without invalidating immutable published metadata', async () => {
  const product = await companies.create({ name: 'Real allocation app', vendor: 'Vendor', description: '', totalSeats: 2, reason }, state.user, bearer);
  const created = await create(draft({ appPoolIds: [product.id] })); await change('published', created.blueprintId, {}, '1'); const released = await store.version(created.blueprintId, 1, state.user, bearer);
  const userId = randomUUID(); state.targets.set(userId, { id: userId, revision: '1', eligibilityRevision: '1', enabled: true, deleted: false });
  const assigned = await companies.assign(product.id, { userId, reason, confirm: true }, require('../../../../../packages/company-license-contract').poolEtag(product), state.user, bearer);
  assert.equal(assigned.revision, '2'); assert.equal(assigned.usedSeats, 1); assert.deepEqual(await store.version(created.blueprintId, 1, state.user, bearer), released); assert.equal((await store.get(created.blueprintId, state.user, bearer)).blueprint.publishedVersion, 1);
});
test('real elapsed original source expiry leaves historical reads and effect-free recovery available under fresh current authority', async () => {
  state.source.validUntil = Math.floor(Date.now() / 1000) + 2; const deadline = state.source.validUntil; const id = randomUUID(); const operation = randomUUID(); const document = draft(); await create(document, id, operation);
  await new Promise(resolve => setTimeout(resolve, Math.max(0, deadline * 1000 - Date.now() + 30)));
  const now = Math.floor(Date.now() / 1000); state.user.auth_time = now; state.user.mfa_authorization.authTime = now; state.user.jti = randomUUID(); state.source.tokenId = state.user.jti; state.source.validUntil = now + 300;
  assert.ok(deadline * 1000 < Date.now()); assert.equal((await store.get(id, state.user, bearer)).blueprint.revision, '1'); assert.equal((await store.history(id, {}, state.user, bearer)).total, 1);
  assert.equal((await create(document, id, operation)).outcome, 'already_applied'); assert.equal((await store.history(id, {}, state.user, bearer)).total, 1);
});
test('canonical SQL payload equality refuses a formatting-only draft update with the same captured configuration ID', async () => {
  const item = configuration(); const created = await create(draft({ configurations: [item] }));
  await assert.rejects(change('updated', created.blueprintId, { draft: draft({ configurations: [{ ...item, payloadJson: '{ "requirePassword" : true, "minutes" : 5 }' }] }) }, '1'), { status: 409 });
  assert.equal((await store.history(created.blueprintId, {}, state.user, bearer)).total, 1);
});
