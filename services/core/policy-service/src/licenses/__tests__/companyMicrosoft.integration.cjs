'use strict';

const { test, beforeEach, afterEach, after } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { Pool } = require('pg');
const { LicenseAllocator } = require('../LicenseAllocator');
const { CompanyLicenses } = require('../CompanyLicenses');
const { CompanyMicrosoftBridge } = require('../CompanyMicrosoftBridge');
const { COMPANY_LICENSE_PERMISSIONS } = require('../../../../../../packages/company-license-contract');
const express = require('express'); const request = require('supertest');

const admin = new Pool({ connectionString: process.env.LICENSE_TEST_DATABASE_URL, max: 1 });
let pool, schema, database, source, user, target, companies, bridge, sku, remoteId, calls, delayCommit;
beforeEach(async () => {
  schema = 'company_microsoft_' + randomUUID().replaceAll('-', ''); await admin.query('CREATE SCHEMA ' + schema);
  pool = new Pool({ connectionString: process.env.LICENSE_TEST_DATABASE_URL, options: '-c search_path=' + schema + ',public', max: 5 });
  for (const name of fs.readdirSync(path.join(__dirname, '../../db/migrations')).filter(value => value.endsWith('.sql')).sort()) await pool.query(fs.readFileSync(path.join(__dirname, '../../db/migrations', name), 'utf8'));
  delayCommit = null;
  database = { query: (...args) => pool.query(...args), getClient: async () => {
    const client = await pool.connect(); return { query: async (...args) => { if (args[0] === 'COMMIT' && delayCommit) await delayCommit(); return client.query(...args); }, release: () => client.release() };
  } };
  const now = Math.floor(Date.now() / 1000), actor = randomUUID(); target = randomUUID(); remoteId = randomUUID(); calls = [];
  user = { actor_type: 'user', iss: 'https://company-microsoft.fixture', sub: 'explicit-company-owner', jti: randomUUID(), auth_time: now, exp: now + 3600,
    identity_authorization: { userId: actor, revision: '1', linkRevision: '1', rolesRevision: 'a'.repeat(64) } };
  source = { schemaVersion: 1, issuer: user.iss, subject: user.sub, tokenId: user.jti, expiresAt: user.exp, context: user.identity_authorization,
    actorUserId: actor, tenant: { id: randomUUID(), version: '1', generation: '1' }, permissions: [...COMPANY_LICENSE_PERMISSIONS], validUntil: now + 300, target: null };
  const authority = { read: async (_authorization, _user, requested = null) => {
    if (requested !== null && requested !== target) throw Object.assign(new Error('Own target required'), { status: 404 });
    return structuredClone({ ...source, target: requested === null ? null : { id: target, revision: '1', eligibilityRevision: '1', enabled: true, deleted: false } });
  } };
  const allocator = new LicenseAllocator(database); companies = new CompanyLicenses(allocator, { authority });
  sku = { skuId: randomUUID(), skuPartNumber: 'BUSINESS', appliesTo: 'User', capabilityStatus: 'Enabled', prepaidUnits: { enabled: 10, warning: 0, suspended: 0, lockedOut: 0 }, consumedUnits: 1 };
  const tenantId = randomUUID(), readId = randomUUID(), writeId = randomUUID();
  bridge = new CompanyMicrosoftBridge(companies, { tenantId: source.tenant.id, readFilename: 'read.fixture', writeFilename: 'write.fixture',
    load: name => ({ schemaVersion: 1, provider: 'microsoft-365', tenantId, clientId: name === 'read.fixture' ? readId : writeId, clientSecret: 'explicit-fixture-secret', consentReviewed: true }),
    createReader: () => ({ inspect: async () => { calls.push('capacity'); return [structuredClone(sku)]; } }),
    createGraph: () => ({ readUser: async id => { calls.push(id); return { id, accountEnabled: true }; } }),
  });
});
afterEach(async () => { await pool.end(); await admin.query('DROP SCHEMA ' + schema + ' CASCADE'); });
after(async () => admin.end());
const input = () => ({ reason: 'Explicit native company Microsoft binding review', confirm: true });
const connectionInput = () => { const config = bridge.configurations(source); return { ...input(), microsoftTenantId: config.read.tenantId, readClientId: config.read.clientId, writeClientId: config.write.clientId }; };
const connect = () => bridge.connect(connectionInput(), randomUUID(), user, 'Bearer explicit-company-fixture');
const connectionVersion = async (revision = '1') => ({ id: (await bridge.state(user, 'Bearer explicit-company-fixture')).connection.id, revision });
const createPool = () => companies.create({ name: 'Native Microsoft pool', vendor: 'Microsoft', description: '', totalSeats: 2, reason: 'Actual company catalog fixture' }, user, 'Bearer explicit-company-fixture');

test('company Microsoft metadata binds the operator-selected tenant, own pool and reviewed user with retained audit', async () => {
  const local = await createPool(); const key = randomUUID();
  const connected = await bridge.connect(connectionInput(), key, user, 'Bearer explicit-company-fixture');
  assert.equal((await bridge.connect(connectionInput(), key, user, 'Bearer explicit-company-fixture')).historical, true);
  const product = await bridge.bindPool(local.id, { ...input(), skuId: sku.skuId, exclusiveDirectManagement: true }, await connectionVersion(), randomUUID(), user, 'Bearer explicit-company-fixture');
  const person = await bridge.bindUser(target, { ...input(), objectId: remoteId, exclusiveDirectManagement: true }, await connectionVersion(), randomUUID(), user, 'Bearer explicit-company-fixture');
  assert.equal(product.pool.poolId, local.id); assert.equal(person.user.objectId, remoteId);
  const current = await bridge.state(user, 'Bearer explicit-company-fixture'); assert.equal(current.state, 'connected'); assert.equal(current.connection.id, connected.connection.id);
  const mappings = await bridge.mappings(local.id, { page: '1' }, user, 'Bearer explicit-company-fixture'); assert.equal(mappings.users.length, 1); assert.equal(mappings.pool.skuId, sku.skuId);
  const history = await bridge.history({ page: '1' }, user, 'Bearer explicit-company-fixture'); assert.equal(history.events.length, 3); assert.ok(history.events.every(value => value.actorUserId === source.actorUserId));
  const records = JSON.stringify((await pool.query('SELECT source,request,outcome FROM company_microsoft_operations')).rows);
  assert.equal(records.includes('explicit-fixture-secret'), false); assert.equal(records.includes('Bearer explicit-company-fixture'), false);
});

test('foreign targets, unsupported selectors and stale connection revisions make no provider request', async () => {
  const local = await createPool(); await connect(); calls = [];
  await assert.rejects(bridge.connect({ ...connectionInput(), tenantId: randomUUID() }, randomUUID(), user, 'Bearer explicit-company-fixture'));
  await assert.rejects(bridge.bindUser(randomUUID(), { ...input(), objectId: remoteId, exclusiveDirectManagement: true }, await connectionVersion(), randomUUID(), user, 'Bearer explicit-company-fixture'), error => error.status === 404);
  await assert.rejects(bridge.bindPool(local.id, { ...input(), skuId: sku.skuId, exclusiveDirectManagement: true }, await connectionVersion('9'), randomUUID(), user, 'Bearer explicit-company-fixture'), error => error.status === 412);
  await assert.rejects(bridge.bindPool(local.id, { ...input(), skuId: sku.skuId, exclusiveDirectManagement: true }, { id: randomUUID(), revision: '1' }, randomUUID(), user, 'Bearer explicit-company-fixture'), error => error.status === 412);
  assert.deepEqual(calls, []);
});

test('reapplying the metadata migration preserves receipts and denies a legacy worker every company Microsoft function', async () => {
  const connected = await connect();
  await pool.query(fs.readFileSync(path.join(__dirname, '../../db/migrations/031_company_microsoft.sql'), 'utf8'));
  assert.equal((await bridge.state(user, 'Bearer explicit-company-fixture')).connection.id, connected.connection.id);
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM company_microsoft_events')).rows[0].count, 1);
  const role = 'microsoft_legacy_' + randomUUID().replaceAll('-', ''); let limited;
  await admin.query(`CREATE ROLE ${role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOINHERIT`);
  try {
    const grants = fs.readFileSync(path.join(__dirname, '../../../scripts/license-fulfillment-grants.sql'), 'utf8').replaceAll(':"license_schema"', `"${schema}"`).replaceAll(':"worker_role"', `"${role}"`); await pool.query(grants);
    const url = new URL(process.env.LICENSE_TEST_DATABASE_URL); url.username = role; url.password = '';
    limited = new Pool({ connectionString: url.toString(), max: 1, options: '-c search_path=' + schema + ',public' });
    const signatures = (await pool.query('SELECT signature FROM company_microsoft_receiver_manifest')).rows;
    for (const row of signatures) assert.equal((await limited.query("SELECT has_function_privilege(current_user,to_regprocedure($1),'EXECUTE') AS allowed", [row.signature])).rows[0].allowed, false, row.signature);
    await assert.rejects(limited.query('SELECT * FROM company_microsoft_connections'), error => error.code === '42501');
    await assert.rejects(limited.query('SELECT company_microsoft_receiving()'), error => error.code === '42501');
  } finally {
    if (limited) await limited.end(); await pool.query(`DROP OWNED BY ${role}`); await admin.query(`DROP ROLE ${role}`);
  }
});

test('Microsoft configuration cannot be rewritten directly and its audit cannot be erased', async () => {
  const connected = await connect();
  await assert.rejects(pool.query('UPDATE company_microsoft_connections SET read_client_id=$2 WHERE id=$1', [connected.connection.id, randomUUID()]), error => error.code === '42501');
  await assert.rejects(pool.query('DELETE FROM company_microsoft_events'), error => error.code === '42501');
  await assert.rejects(pool.query('TRUNCATE company_microsoft_events CASCADE'), error => error.code === '42501');
  await pool.query('ALTER TABLE company_microsoft_events DISABLE TRIGGER company_microsoft_guard');
  await assert.rejects(bridge.state(user, 'Bearer explicit-company-fixture'), error => error.code === '42501');
  await pool.query('ALTER TABLE company_microsoft_events ENABLE TRIGGER company_microsoft_guard');
  assert.equal((await bridge.state(user, 'Bearer explicit-company-fixture')).state, 'connected');
});

test('mapping retirement precedes disconnection and keeps the original receipts', async () => {
  const local = await createPool(), connection = (await connect()).connection;
  const product = (await bridge.bindPool(local.id, { ...input(), skuId: sku.skuId, exclusiveDirectManagement: true }, await connectionVersion(), randomUUID(), user, 'Bearer explicit-company-fixture')).pool;
  await assert.rejects(bridge.retire('connection', connection.id, '1', randomUUID(), input(), user, 'Bearer explicit-company-fixture'), error => error.code === '23514');
  assert.equal((await bridge.retire('pool', product.id, '1', randomUUID(), input(), user, 'Bearer explicit-company-fixture')).binding.status, 'retired');
  assert.equal((await bridge.retire('connection', connection.id, '1', randomUUID(), input(), user, 'Bearer explicit-company-fixture')).binding.status, 'disconnected');
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM company_microsoft_operations')).rows[0].count, 4);
});

test('the mounted company HTTP API persists only the reviewed Microsoft configuration and rejects changed public IDs', async () => {
  const app = express(); app.use(express.json()); app.use((req, _res, next) => { req.user = user; next(); });
  const options = Object.fromEntries(['tenantId', 'readFilename', 'writeFilename', 'load', 'createReader', 'createGraph'].map(key => [key, bridge[key]]));
  app.use('/api/licenses/company', require('../companyRoutes').companyLicenseRoutes(companies.allocator, { authority: companies.authority, microsoft: options }));
  const base = '/api/licenses/company/provider/microsoft'; const local = await createPool();
  const before = await request(app).get(base + '/state').set('Authorization', 'Bearer explicit-company-fixture'); assert.equal(before.status, 200); assert.equal(before.body.state, 'configured');
  const wrong = await request(app).post(base + '/connections').set('Idempotency-Key', randomUUID()).send({ ...connectionInput(), microsoftTenantId: randomUUID() }); assert.equal(wrong.status, 412); assert.deepEqual(calls, []);
  const connected = await request(app).post(base + '/connections').set('Idempotency-Key', randomUUID()).send(connectionInput()); assert.equal(connected.status, 201); assert.equal(connected.headers['cache-control'], 'no-store');
  const bound = await request(app).post(base + '/pools/' + local.id + '/bind').set('If-Match', connected.headers.etag).set('Idempotency-Key', randomUUID()).send({ ...input(), skuId: sku.skuId, exclusiveDirectManagement: true });
  assert.equal(bound.status, 201); assert.equal(bound.body.pool.poolId, local.id);
  const rows = await request(app).get(base + '/pools/' + local.id + '/mappings?page=1'); assert.equal(rows.status, 200); assert.equal(rows.body.pool.id, bound.body.pool.id);
  const history = await request(app).get(base + '/history?page=1'); assert.equal(history.status, 200); assert.equal(history.body.events.length, 2);
});

test('receiving rejects a correctly named commit trigger that omits updates', async () => {
  await pool.query('DROP TRIGGER company_microsoft_commit_guard ON company_microsoft_operations');
  await pool.query('CREATE CONSTRAINT TRIGGER company_microsoft_commit_guard AFTER INSERT ON company_microsoft_operations DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION company_microsoft_commit_guard()');
  await assert.rejects(bridge.state(user, 'Bearer explicit-company-fixture'), error => error.code === '42501');
});

test('MFA source expiry before the physical SQL commit rolls back configuration and every receipt', async () => {
  source.validUntil = Math.floor(Date.now() / 1000) + 2;
  delayCommit = () => new Promise(resolve => setTimeout(resolve, Math.max(0, source.validUntil * 1000 - Date.now() + 40)));
  await assert.rejects(connect(), error => error.code === '42501' && error.message.includes('expired before commit'));
  for (const table of ['company_microsoft_connections', 'company_microsoft_operations', 'company_microsoft_events', 'company_microsoft_outbox']) {
    assert.equal((await pool.query('SELECT count(*)::int AS count FROM ' + table)).rows[0].count, 0);
  }
});
