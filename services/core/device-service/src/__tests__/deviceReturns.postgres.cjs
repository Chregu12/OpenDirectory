'use strict';

const { test, beforeEach, afterEach, after } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { Pool } = require('pg');
const { DeviceInventory } = require('../DeviceInventory');
const { InventoryAuthority } = require('../InventoryAuthority');
const { DeviceReturns } = require('../DeviceReturns');
const { DeviceReturnAuthority } = require('../DeviceReturnAuthority');
const { INVENTORY_PERMISSIONS, deviceEtag, deviceReturnEtag } = require('../../../../../packages/device-inventory-contract');

assert.ok(process.env.DEVICE_TEST_DATABASE_URL, 'Use scripts/test-returns-postgres.js');
const administration = new Pool({ connectionString: process.env.DEVICE_TEST_DATABASE_URL, max: 1 });
const relations = ['devices', 'device_inventory_assignments', 'device_inventory_events', 'device_inventory_outbox', 'device_return_requests', 'device_return_events', 'device_return_outbox'];
const bearer = 'Bearer returns.explicit.native.fixture';
const reason = 'Collect original laptop at reception';
let schema; let pool; let fixture; let database; let inventory; let service;

function authorityFixture() {
  const now = Math.floor(Date.now() / 1000); const actor = randomUUID(); const userId = randomUUID(); const workflowId = randomUUID();
  const user = { actor_type: 'user', iss: 'https://returns.fixture.test', sub: 'actual-native-operator', jti: randomUUID(), exp: now + 3600, auth_time: now,
    identity_authorization: { userId: actor, revision: '1', linkRevision: '1', rolesRevision: 'a'.repeat(64) } };
  const source = { schemaVersion: 1, issuer: user.iss, subject: user.sub, tokenId: user.jti, expiresAt: user.exp, context: structuredClone(user.identity_authorization),
    tenant: { id: randomUUID(), version: '1', generation: '1' }, actorUserId: actor, permissions: [...INVENTORY_PERMISSIONS], validUntil: now + 300, target: null };
  const state = { user, source, userId, nextUserId: randomUUID(), workflowId, eligibility: '7', targetEnabled: false, revoked: false, calls: [], transactions: [], beforeCommit: null, beforeCheckpoint: null, afterCommit: null, errors: [] };
  state.negative = () => ({ ...structuredClone(source), target: { id: userId, enabled: false, eligibilityRevision: state.eligibility }, deviceOffboardingReturnsProtocol: 1,
    parent: { workflowId, tenantId: source.tenant.id, userId, action: 'disabled', operationId: state.parentOperationId, afterRevision: '5', afterEligibilityRevision: state.eligibility, createdAt: state.parentTime, deliveryStatus: 'pending' } });
  state.parentOperationId = randomUUID(); state.parentTime = new Date((now - 2) * 1000).toISOString();
  const fetchImpl = async (url, request) => {
    assert.equal(request.headers.Authorization, bearer); assert.equal(request.redirect, 'error'); assert.equal(request.cache, 'no-store');
    const negative = url.pathname.endsWith('/device-offboarding'); const body = request.body ? JSON.parse(request.body) : null;
    let status = state.revoked ? 401 : negative && state.targetEnabled ? 409 : 200;
    if (body && (negative ? body.userId !== userId || body.workflowId !== workflowId : ![userId,state.nextUserId].includes(body.userId))) status = 404;
    state.calls.push({ negative, body, status });
    const value = negative ? state.negative() : { ...structuredClone(source), target: body ? { id: body.userId, revision: '3', enabled: body.userId === userId ? state.targetEnabled : true } : null };
    return Response.json(status === 200 ? value : { error: 'Explicit canonical fixture rejected request' }, { status });
  };
  state.inventoryAuthority = new InventoryAuthority({ endpoint: 'https://returns.fixture.test/api/identity/device-inventory', fetchImpl });
  state.returnAuthority = new DeviceReturnAuthority({ endpoint: 'https://returns.fixture.test/api/identity/device-offboarding', fetchImpl }); return state;
}

function nativeDatabase() {
  return { isAvailable: () => true, transaction: async (operation, { readOnly = false, beforeCommit } = {}) => {
    const client = await pool.connect(); const trace = { readOnly, committed: false }; fixture.transactions.push(trace);
    try {
      await client.query(readOnly ? 'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY' : 'BEGIN');
      await client.query("SET LOCAL lock_timeout='5s'"); await client.query("SET LOCAL statement_timeout='15s'");
      const result = await operation(client);
      if (!readOnly && fixture.beforeCheckpoint) await fixture.beforeCheckpoint(client);
      if (beforeCommit) await beforeCommit(client);
      if (!readOnly && fixture.beforeCommit) await fixture.beforeCommit(client);
      await client.query('COMMIT'); trace.committed = true; if (!readOnly && fixture.afterCommit) await fixture.afterCommit(result); return result;
    } catch (error) { fixture.errors.push(error); await client.query('ROLLBACK'); throw error; }
    finally { client.release(); }
  } };
}

async function migrate() {
  for (const file of ['001_devices.sql', '002_device_system_info.sql', '003_device_columns_align.sql', '004_install_jobs.sql', '005_device_inventory.sql', '006_device_returns.sql']) await pool.query(fs.readFileSync(path.join(__dirname, '../../migrations', file), 'utf8'));
}
async function assigned() {
  const suffix = randomUUID(); const unit = await inventory.create({ assetId: `Asset-${suffix}`, serialNumber: `Serial-${suffix}`, manufacturer: 'Native', model: 'Portable', deviceClass: 'laptop', platform: 'linux' }, fixture.user, bearer);
  return inventory.assign(unit.id, { userId: fixture.userId }, deviceEtag(unit), fixture.user, bearer);
}
function manifest(unit, requestId = randomUUID()) { return { workflowId: fixture.workflowId, eligibilityRevision: fixture.eligibility, reason, confirm: true, items: [{ deviceId: unit.id, deviceRevision: unit.revision, assignmentId: unit.assignmentId, requestId }] }; }
async function requested(unit = null) {
  unit ||= await assigned(); const body = manifest(unit); const result = await service.request(fixture.userId, body, fixture.user, bearer);
  assert.equal(result.results[0].status, 'requested', JSON.stringify(fixture.errors.at(-1))); return { unit, body, request: await service.get(body.items[0].requestId, fixture.user, bearer) };
}
function decision(request, action = 'returned', expected = deviceReturnEtag(request), decisionReason = 'Received original device at reception') {
  return service.decide(request.id, { action, reason: decisionReason, confirm: true }, expected, fixture.user, bearer);
}
async function snapshot() {
  const values = {};
  for (const relation of relations) values[relation] = (await pool.query(`SELECT to_jsonb(actual) AS state FROM ${relation} actual ORDER BY id`)).rows;
  return values;
}
async function proof(unit) {
  const body = manifest(unit); return { id: randomUUID(), action: 'requested', requestId: body.items[0].requestId, correlationId: randomUUID(), source: fixture.negative(), item: body.items[0], reason, eligibilityRevision: fixture.eligibility };
}
async function sqlProof(value, extra = async () => {}) {
  return database.transaction(async client => { await client.query('SELECT device_returns_change($1::jsonb)', [JSON.stringify(value)]); await extra(client); });
}
async function trigger(relation, body, timing = 'BEFORE INSERT') {
  await pool.query(`CREATE FUNCTION returns_native_fixture() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN ${body} END; $$`);
  await pool.query(`CREATE TRIGGER zzz_returns_native_fixture ${timing} ON ${relation} FOR EACH ROW EXECUTE FUNCTION returns_native_fixture()`);
}

beforeEach(async () => {
  schema = 'device_returns_' + randomUUID().replaceAll('-', ''); await administration.query(`CREATE SCHEMA ${schema}`);
  const url = new URL(process.env.DEVICE_TEST_DATABASE_URL); url.searchParams.set('options', `-c search_path=${schema},public -c timezone=UTC`);
  pool = new Pool({ connectionString: url.toString(), max: 8 }); await migrate(); fixture = authorityFixture(); database = nativeDatabase();
  inventory = new DeviceInventory(database, { authority: fixture.inventoryAuthority }); service = new DeviceReturns(database, { inventory, authority: fixture.returnAuthority });
});
afterEach(async () => { if (pool) await pool.end(); if (schema) await administration.query(`DROP SCHEMA ${schema} CASCADE`); });
after(async () => { await administration.end(); });

test('006 replay retains all original inventory evidence and receiving functions', async () => {
  const { request } = await requested(); const before = await snapshot(); await migrate(); assert.deepEqual(await snapshot(), before);
  await pool.query('ALTER TABLE device_return_events DROP COLUMN version'); await migrate(); assert.deepEqual(await snapshot(), before);
  assert.deepEqual((await pool.query('SELECT version FROM device_return_events')).rows, [{ version: 1 }]);
  assert.equal((await service.history(request.id, {}, fixture.user, bearer)).events[0].version, 1);
  assert.equal((await service.get(request.id, fixture.user, bearer)).operationId, request.operationId); await pool.query('SELECT device_returns_receiving()');
});
test('request creation is metadata only, exact bigint-safe DTO and actual event/outbox', async () => {
  const unit = await assigned(); const before = await inventory.get(unit.id, fixture.user, bearer); const { request } = await requested(unit);
  assert.deepEqual(await inventory.get(unit.id, fixture.user, bearer), before); assert.equal(request.status, 'requested'); assert.equal(request.revision, '1');
  assert.deepEqual([request.deviceRevision, request.currentDeviceRevision], ['2', '2']); assert.equal(request.closingOperationId, null); assert.equal(request.inventoryOperationId, null); assert.equal(request.closedAt, null);
  assert.deepEqual(Object.keys(request), ['id','tenantId','workflowId','userId','deviceId','assignmentId','assetId','serialNumber','revision','deviceRevision','currentDeviceRevision','status','reason','actorUserId','requestedAt','eligibilityRevision','closedAt','closedByUserId','operationId','closingOperationId','inventoryOperationId','deliveryStatus']);
  const history = await service.history(request.id, {}, fixture.user, bearer); assert.equal(history.events.length, 1); assert.equal(history.events[0].id, request.operationId);
  assert.equal(history.events[0].version, 1);
  assert.deepEqual(Object.keys(history.events[0]), ['id','tenantId','requestId','deviceId','assignmentId','type','version','actorUserId','correlationId','createdAt','before','after','inventoryOperationId','reason','deliveryStatus']);
  assert.deepEqual(history.events[0].after, { revision: '1', status: 'requested' }); assert.equal(history.events[0].before, null); assert.equal(history.events[0].deliveryStatus, 'pending');
  assert.equal((await pool.query('SELECT count(*) FROM device_inventory_events')).rows[0].count, '2');
});
test('confirmed return composes actual old005 release with exactly two return receipts and revision2', async () => {
  const { unit, request } = await requested(); const result = await decision(request); assert.equal(result.outcome, 'returned'); assert.equal(result.request.status, 'returned');
  assert.equal(result.request.revision, '2'); assert.equal(result.request.deviceRevision, '2'); assert.equal(result.request.currentDeviceRevision, '3'); assert.equal(result.operationId, result.request.closingOperationId);
  assert.equal((await inventory.get(unit.id, fixture.user, bearer)).assignedUserId, null);
  const row = (await pool.query('SELECT decision.transaction_id::text AS decision_tx, inventory.transaction_id::text AS inventory_tx, inventory.action, inventory.before_assignment FROM device_return_events decision JOIN device_inventory_events inventory ON inventory.id=decision.inventory_operation_id WHERE decision.id=$1', [result.operationId])).rows[0];
  assert.equal(row.decision_tx, row.inventory_tx); assert.equal(row.action, 'release'); assert.equal(row.before_assignment.id, request.assignmentId);
  const history = await service.history(request.id, {}, fixture.user, bearer); assert.deepEqual(history.events.map(event => event.type), ['device.return.requested', 'device.return.confirmed']);
  assert.deepEqual(history.events.map(event => event.version), [1, 1]);
});
test('cancellation changes no inventory and allows a new explicit request UUID', async () => {
  const { unit, request } = await requested(); const before = await inventory.get(unit.id, fixture.user, bearer); const result = await decision(request, 'cancelled');
  assert.equal(result.request.inventoryOperationId, null); assert.equal(result.request.status, 'cancelled'); assert.deepEqual(await inventory.get(unit.id, fixture.user, bearer), before);
  assert.deepEqual((await service.history(request.id, {}, fixture.user, bearer)).events.map(event => event.version), [1, 1]);
  const next = await requested(unit); assert.notEqual(next.request.id, request.id);
});
test('direct returneddecision without optional correlation shares one actual correlation across005 and006 events', async () => {
  const { request } = await requested();
  const result = await service.decide(request.id, { action: 'returned', reason: 'Received original device at reception', confirm: true }, deviceReturnEtag(request), fixture.user, bearer);
  const actual = (await pool.query('SELECT decision.correlation_id AS return_correlation, inventory.correlation_id AS inventory_correlation FROM device_return_events decision JOIN device_inventory_events inventory ON inventory.id=decision.inventory_operation_id WHERE decision.id=$1', [result.operationId])).rows[0];
  assert.match(actual.return_correlation, /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/); assert.equal(actual.return_correlation, actual.inventory_correlation);
});
test('creation oldid recovery preserves original event and never queues a later assignment', async () => {
  const { unit, request, body } = await requested(); await inventory.assign(unit.id, { userId: null }, deviceEtag(unit), fixture.user, bearer);
  const released = await inventory.get(unit.id, fixture.user, bearer); const replacement = await inventory.assign(unit.id, { userId: fixture.userId }, deviceEtag(released), fixture.user, bearer);
  const before = await snapshot(); const recovered = await service.request(fixture.userId, body, fixture.user, bearer);
  assert.equal(recovered.results[0].status, 'already_requested'); assert.equal(recovered.results[0].operationId, request.operationId); assert.deepEqual(await snapshot(), before);
  assert.equal((await inventory.get(unit.id, fixture.user, bearer)).assignmentId, replacement.assignmentId);
});
test('unknown decision acknowledgement recovers only originaletag action and reason without touching a replacement', async () => {
  const { unit, request } = await requested(); const first = await decision(request); const current = await inventory.get(unit.id, fixture.user, bearer);
  const replacement = await inventory.assign(unit.id, { userId: fixture.userId }, deviceEtag(current), fixture.user, bearer); const before = await snapshot();
  const recovered = await decision(request); assert.equal(recovered.outcome, 'already_returned'); assert.equal(recovered.operationId, first.operationId); assert.equal(recovered.request.currentDeviceRevision, replacement.revision); assert.deepEqual(await snapshot(), before);
  await assert.rejects(decision(request, 'returned', deviceReturnEtag(first.request)), { status: 409 });
  await assert.rejects(decision(request, 'returned', deviceReturnEtag(request), 'Changed received reason'), { status: 409 });
  await assert.rejects(decision(request, 'cancelled'), { status: 409 });
});
test('cancel recovery is effect-free and immutable', async () => {
  const { request } = await requested(); const first = await decision(request, 'cancelled'); const before = await snapshot(); const second = await decision(request, 'cancelled');
  assert.equal(second.outcome, 'already_cancelled'); assert.equal(second.operationId, first.operationId); assert.deepEqual(await snapshot(), before);
});
test('ordinary release derives assignment_changed from its real005 event and never fabricates confirmation', async () => {
  const { unit, request } = await requested(); await inventory.assign(unit.id, { userId: null }, deviceEtag(unit), fixture.user, bearer);
  const actual = await service.get(request.id, fixture.user, bearer); assert.equal(actual.status, 'assignment_changed'); assert.equal(actual.revision, '1'); assert.equal(actual.closingOperationId, null); assert.ok(actual.inventoryOperationId);
  const history = await service.history(request.id, {}, fixture.user, bearer); assert.deepEqual(history.events.map(event => event.type), ['device.return.requested']);
  await assert.rejects(decision(actual), { status: 409 }); await assert.rejects(decision(actual, 'cancelled'), { status: 409 });
  assert.equal((await service.list({ status: 'assignment_changed' }, fixture.user, bearer)).total, 1);
});
test('ordinary reassignment is never blocked and its new exclusive assignment is untouchable', async () => {
  const { unit, request } = await requested(); const released = await inventory.assign(unit.id, { userId: null }, deviceEtag(unit), fixture.user, bearer);
  const replacement = await inventory.assign(unit.id, { userId: fixture.userId }, deviceEtag(released), fixture.user, bearer); const before = await snapshot();
  await assert.rejects(decision(request), { status: 409 }); assert.deepEqual(await snapshot(), before); assert.equal((await service.get(request.id, fixture.user, bearer)).currentDeviceRevision, replacement.revision);
});
test('general decisions remain legitimate after reactivation but newoffboarding creation and recovery fail', async () => {
  const { request, body } = await requested(); fixture.targetEnabled = true;
  await assert.rejects(service.offboardingList(fixture.userId, { workflowId: fixture.workflowId }, fixture.user, bearer), { status: 409 });
  await assert.rejects(service.request(fixture.userId, body, fixture.user, bearer), { status: 409 });
  assert.equal((await decision(request)).outcome, 'returned');
});
test('wholemanifest repeatableread stale-last-item preflight has no first-child effect', async () => {
  const first = await assigned(); const last = await assigned(); const body = manifest(first); body.items.push({ ...manifest(last).items[0], deviceRevision: '1' }); const before = await snapshot();
  await assert.rejects(service.request(fixture.userId, body, fixture.user, bearer), { status: 409 }); assert.deepEqual(await snapshot(), before);
  assert.equal(fixture.transactions.at(-1).readOnly, true);
});
test('perchild commit persists earlier request then unconfirmed stops later children', async () => {
  const first = await assigned(); const second = await assigned(); const third = await assigned(); const body = manifest(first); body.items.push(manifest(second).items[0], manifest(third).items[0]);
  await trigger('device_return_events', `IF NEW.device_id='${second.id}' THEN RAISE EXCEPTION 'second child refused' USING ERRCODE='23514'; END IF; RETURN NEW;`);
  const result = await service.request(fixture.userId, body, fixture.user, bearer); assert.deepEqual(result.results.map(item => item.status), ['requested','unconfirmed','not_attempted']);
  assert.equal(result.results[1].code, 409); assert.equal(result.results[2].code, null); assert.equal((await pool.query('SELECT count(*) FROM device_return_requests')).rows[0].count, '1');
});
test('only one requested task per original assignment and requestuuid intent is immutable', async () => {
  const { unit, body } = await requested(); const before = await snapshot();
  await assert.rejects(service.request(fixture.userId, manifest(unit), fixture.user, bearer), { status: 409 });
  await assert.rejects(service.request(fixture.userId, { ...body, reason: 'Different creation reason' }, fixture.user, bearer), { status: 409 }); assert.deepEqual(await snapshot(), before);
});
test('disabled generation mismatch and foreign workflownamespace reject without metadata writes', async () => {
  const unit = await assigned(); const body = manifest(unit); const before = await snapshot(); fixture.eligibility = '8';
  await assert.rejects(service.request(fixture.userId, body, fixture.user, bearer), { status: 409 });
  await assert.rejects(service.offboardingCapabilities(fixture.userId, { workflowId: randomUUID() }, fixture.user, bearer), { status: 404 }); assert.deepEqual(await snapshot(), before);
});
test('general receiver remains tenant scoped even for a valid original operator', async () => {
  const { request } = await requested(); fixture.source.tenant = { id: randomUUID(), version: '1', generation: '1' };
  assert.equal((await service.list({}, fixture.user, bearer)).total, 0); await assert.rejects(service.get(request.id, fixture.user, bearer), { status: 404 }); await assert.rejects(decision(request), { status: 404 });
});
test('offboarding preview uses actual assignments and shows pending originalrequest without making inventory available', async () => {
  const { unit, request } = await requested(); const preview = await service.offboardingList(fixture.userId, { workflowId: fixture.workflowId }, fixture.user, bearer);
  assert.equal(preview.devices[0].openRequestId, request.id); assert.equal(preview.devices[0].assignmentId, unit.assignmentId); assert.equal(preview.target.eligibilityRevision, fixture.eligibility);
  const history = await service.offboardingHistory(fixture.userId, { workflowId: fixture.workflowId }, fixture.user, bearer); assert.deepEqual(history.requests, [request]);
});
test('general capabilities have only fixed3 permissions and no management command claims', async () => {
  assert.deepEqual(await service.capabilities(fixture.user, bearer), { schemaVersion: 1, deviceReturnsProtocol: 1, actorUserId: fixture.source.actorUserId, tenantId: fixture.source.tenant.id, permissions: [...INVENTORY_PERMISSIONS], managementMode: 'inventory-only' });
});
test('stale combinedrequest/device etag and missing confirmation never reach release', async () => {
  const { request } = await requested(); const before = await snapshot();
  await assert.rejects(decision(request, 'returned', `"device-return-${request.id}-1-1"`), { status: 412 });
  await assert.rejects(service.decide(request.id, { action: 'returned', reason, confirm: false }, deviceReturnEtag(request), fixture.user, bearer), { status: 400 });
  await assert.rejects(service.decide(request.id, { action: 'returned', reason, confirm: true }, undefined, fixture.user, bearer), { status: 428 }); assert.deepEqual(await snapshot(), before);
});
test('fresh authority loss after nested release rolls back all old005 and new006 effects', async () => {
  const { request } = await requested(); const before = await snapshot(); fixture.beforeCheckpoint = async () => { fixture.revoked = true; };
  await assert.rejects(decision(request), { status: 401 }); fixture.revoked = false; assert.deepEqual(await snapshot(), before);
});
test('fresh negativeparent source loss at outercheckpoint rolls back metadata creation', async () => {
  const unit = await assigned(); const before = await snapshot(); fixture.beforeCheckpoint = async () => { fixture.targetEnabled = true; };
  const result = await service.request(fixture.userId, manifest(unit), fixture.user, bearer); assert.equal(result.results[0].status, 'unconfirmed'); assert.equal(result.results[0].code, 409); assert.deepEqual(await snapshot(), before);
});
test('raw DML and truncation cannot fabricate, mutate or erase return evidence', async () => {
  const { request } = await requested(); const before = await snapshot();
  for (const sql of ["UPDATE device_return_requests SET status='cancelled'", 'DELETE FROM device_return_requests', 'DELETE FROM device_return_events', 'DELETE FROM device_return_outbox', 'TRUNCATE device_return_outbox']) await assert.rejects(pool.query(sql));
  assert.deepEqual(await snapshot(), before); assert.equal((await service.get(request.id, fixture.user, bearer)).status, 'requested');
});
test('missing pendingoutbox aborts creation at physicalcommit', async () => {
  const unit = await assigned(); const before = await snapshot(); await trigger('device_return_outbox', 'RETURN NULL;');
  const result = await service.request(fixture.userId, manifest(unit), fixture.user, bearer); assert.equal(result.results[0].status, 'unconfirmed'); assert.deepEqual(await snapshot(), before);
});
test('missing decisionoutbox rolls back realnested005 release as well', async () => {
  const { request } = await requested(); const before = await snapshot(); await trigger('device_return_outbox', 'RETURN NULL;');
  await assert.rejects(decision(request)); assert.deepEqual(await snapshot(), before);
});
test('cleared source GUC between computed receipt and COMMIT fails closed', async () => {
  const unit = await assigned(); const before = await snapshot(); fixture.beforeCommit = client => client.query("SELECT set_config('opendirectory.device_returns','',true)");
  const result = await service.request(fixture.userId, manifest(unit), fixture.user, bearer); assert.equal(result.results[0].status, 'unconfirmed'); assert.deepEqual(await snapshot(), before);
});
test('sourceclock expiration at physicalcommit rejects correctly computed pending metadata', async () => {
  const unit = await assigned(); const before = await snapshot(); const value = await proof(unit); value.source.validUntil = Math.floor(Date.now() / 1000) + 2;
  await assert.rejects(sqlProof(value, client => client.query('SELECT pg_sleep(GREATEST(0,$1::double precision-extract(epoch FROM clock_timestamp()))+0.05)', [value.source.validUntil]))); assert.deepEqual(await snapshot(), before);
});
test('missing returnguard is detected before both reads and new writes', async () => {
  const { unit, request } = await requested(); const before = await snapshot(); await pool.query('ALTER TABLE device_return_outbox DISABLE TRIGGER device_returns_guard');
  await assert.rejects(service.get(request.id, fixture.user, bearer), { status: 503 }); await assert.rejects(service.request(fixture.userId, manifest(unit), fixture.user, bearer), { status: 503 }); assert.deepEqual(await snapshot(), before);
});
test('disabled canonical005 guard is detected even for metadata-only return operations', async () => {
  const unit = await assigned(); const before = await snapshot(); await pool.query('ALTER TABLE device_inventory_assignments DISABLE TRIGGER device_inventory_guard');
  await assert.rejects(service.request(fixture.userId, manifest(unit), fixture.user, bearer), { status: 503 }); assert.deepEqual(await snapshot(), before);
});
test('extra inventoryeffect in a metadata child cannot survive physicalcommit', async () => {
  const unit = await assigned(); const value = await proof(unit); const before = await snapshot();
  await assert.rejects(database.transaction(async client => {
    await client.query('SELECT device_returns_change($1::jsonb)', [JSON.stringify(value)]);
    const bound = { isAvailable: () => true, transaction: async (operation, options = {}) => { const result = await operation(client); if (options.beforeCommit) await options.beforeCommit(client); return result; } };
    await new DeviceInventory(bound, { authority: fixture.inventoryAuthority }).assign(unit.id, { userId: null }, deviceEtag(unit), fixture.user, bearer);
  })); assert.deepEqual(await snapshot(), before);
});
test('request source cannot replace exact negative target or smuggle an extra permission', async () => {
  const unit = await assigned(); const before = await snapshot();
  for (const change of [source => { source.target.enabled = true; }, source => { source.permissions.push('admin'); }, source => { source.target.revision = '3'; }, source => { source.parent.tenantId = randomUUID(); }]) {
    const value = await proof(unit); change(value.source); await assert.rejects(sqlProof(value));
  }
  assert.deepEqual(await snapshot(), before);
});
test('retained missing original releaseoutbox makes derived assignmentchanged unavailable', async () => {
  const { unit, request } = await requested(); await inventory.assign(unit.id, { userId: null }, deviceEtag(unit), fixture.user, bearer);
  const releaseId = (await service.get(request.id, fixture.user, bearer)).inventoryOperationId;
  await pool.query('ALTER TABLE device_inventory_outbox DISABLE TRIGGER device_inventory_guard'); await pool.query('DELETE FROM device_inventory_outbox WHERE id=$1', [releaseId]); await pool.query('ALTER TABLE device_inventory_outbox ENABLE TRIGGER device_inventory_guard');
  await assert.rejects(service.get(request.id, fixture.user, bearer));
});
test('retained missing requestoutbox prevents replay acknowledgement', async () => {
  const { request, body } = await requested(); await pool.query('ALTER TABLE device_return_outbox DISABLE TRIGGER device_returns_guard');
  await pool.query('DELETE FROM device_return_outbox WHERE id=$1', [request.operationId]); await pool.query('ALTER TABLE device_return_outbox ENABLE TRIGGER device_returns_guard');
  await assert.rejects(service.request(fixture.userId, body, fixture.user, bearer));
});
test('cancel cannot covertly compose an old005 release', async () => {
  const { unit, request } = await requested(); const before = await snapshot();
  await assert.rejects(database.transaction(async client => {
    const bound = { isAvailable: () => true, transaction: operation => operation(client) };
    await new DeviceInventory(bound, { authority: fixture.inventoryAuthority }).assign(unit.id, { userId: null }, deviceEtag(unit), fixture.user, bearer);
    await client.query('SELECT device_returns_change($1::jsonb)', [JSON.stringify({ id: randomUUID(), action: 'cancelled', requestId: request.id, correlationId: randomUUID(), source: fixture.source, reason, expected: deviceReturnEtag(request), inventoryOperationId: null })]);
  })); assert.deepEqual(await snapshot(), before);
});
test('actual lost commitack is unconfirmed until explicit exact oldid recovery', async () => {
  const unit = await assigned(); const body = manifest(unit); fixture.afterCommit = async () => { throw new Error('Connection lost after committed request'); };
  const uncertain = await service.request(fixture.userId, body, fixture.user, bearer); assert.equal(uncertain.results[0].status, 'unconfirmed'); assert.equal(uncertain.results[0].operationId, null);
  fixture.afterCommit = null; const before = await snapshot(); const recovered = await service.request(fixture.userId, body, fixture.user, bearer);
  assert.equal(recovered.results[0].status, 'already_requested'); assert.deepEqual(await snapshot(), before);
});
test('actual decision lostcommitack can recover without a second release', async () => {
  const { request } = await requested(); fixture.afterCommit = async () => { throw new Error('Connection lost after committed release'); };
  await assert.rejects(decision(request), /Connection lost/); fixture.afterCommit = null; const before = await snapshot(); const recovered = await decision(request);
  assert.equal(recovered.outcome, 'already_returned'); assert.deepEqual(await snapshot(), before);
});
test('same original request concurrent submissions commit one realrequestevent', async () => {
  const unit = await assigned(); const body = manifest(unit); const results = await Promise.all([service.request(fixture.userId, body, fixture.user, bearer), service.request(fixture.userId, body, fixture.user, bearer)]);
  assert.deepEqual(results.map(result => result.results[0].status).sort(), ['already_requested','requested']);
  assert.equal((await pool.query('SELECT count(*) FROM device_return_requests')).rows[0].count, '1'); assert.equal((await pool.query('SELECT count(*) FROM device_return_events')).rows[0].count, '1');
});
test('concurrent returned and cancelled decisions cannot both commit', async () => {
  const { request, unit } = await requested(); const results = await Promise.allSettled([decision(request), decision(request, 'cancelled')]);
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 1); assert.equal(results.filter(result => result.status === 'rejected').length, 1);
  const task = await service.get(request.id, fixture.user, bearer); const actual = await inventory.get(unit.id, fixture.user, bearer);
  assert.equal(actual.assignedUserId, task.status === 'returned' ? null : fixture.userId); assert.equal((await pool.query('SELECT count(*) FROM device_return_events')).rows[0].count, '2');
});
test('a pendingmetadata transaction cannot smuggle a legacydevice write before admission', async () => {
  const unit = await assigned(); const value = await proof(unit); const before = await snapshot();
  await assert.rejects(database.transaction(async client => { await client.query('INSERT INTO devices(id,name) VALUES($1,$2)', [randomUUID(), 'unrelated legacy effect']); await client.query('SELECT device_returns_change($1::jsonb)', [JSON.stringify(value)]); })); assert.deepEqual(await snapshot(), before);
});
test('a returnedtransaction cannot smuggle a different legacydevice write before old005 release', async () => {
  const { request } = await requested(); const before = await snapshot();
  await trigger('device_inventory_events', `INSERT INTO devices(id,name) VALUES('${randomUUID()}','unrelated legacy effect'); RETURN NEW;`);
  await assert.rejects(decision(request)); assert.deepEqual(await snapshot(), before);
});
test('removed physical receivingguard in same child is detected at actualcommit and rolled back', async () => {
  const unit = await assigned(); const before = await snapshot(); fixture.beforeCommit = client => client.query('ALTER TABLE device_return_outbox DISABLE TRIGGER device_returns_guard');
  const result = await service.request(fixture.userId, manifest(unit), fixture.user, bearer); assert.equal(result.results[0].status, 'unconfirmed'); assert.deepEqual(await snapshot(), before); await pool.query('SELECT device_returns_receiving()');
});
test('missing additional inventoryeffect fence is not accepted as receiving readiness', async () => {
  const unit = await assigned(); const before = await snapshot(); await pool.query('ALTER TABLE devices DISABLE TRIGGER device_returns_device_effect');
  await assert.rejects(service.request(fixture.userId, manifest(unit), fixture.user, bearer), { status: 503 }); assert.deepEqual(await snapshot(), before);
});
test('SQLsource rejects nullable or numeric authority counters before creating receipts', async () => {
  const unit = await assigned(); const before = await snapshot();
  for (const change of [source => { source.tenant.version = null; }, source => { source.context.revision = 1; }, source => { source.parent.afterRevision = null; }, source => { source.target.eligibilityRevision = null; }, source => { source.parent.action = null; }]) {
    const value = await proof(unit); change(value.source); await assert.rejects(sqlProof(value));
  }
  assert.deepEqual(await snapshot(), before);
});
test('original snapshot and live version remain exact beyond JavaScript safeinteger in explicit nativeowner fixture', async () => {
  const unit = await assigned(); await pool.query('ALTER TABLE devices DISABLE TRIGGER device_inventory_guard');
  await pool.query("UPDATE devices SET inventory_revision=9007199254740993 WHERE id=$1", [unit.id]); await pool.query('ALTER TABLE devices ENABLE TRIGGER device_inventory_guard');
  fixture.eligibility = '9007199254740995'; const current = await inventory.get(unit.id, fixture.user, bearer); assert.equal(current.revision, '9007199254740993');
  const { request } = await requested(current); assert.equal(request.deviceRevision, '9007199254740993'); assert.equal(request.eligibilityRevision, '9007199254740995');
  const actual = await decision(request); assert.equal(actual.request.currentDeviceRevision, '9007199254740994'); assert.equal(actual.request.deviceRevision, '9007199254740993');
});
test('serverpagination returns25only and unselected26th assignment remains unchanged', async () => {
  const units = []; for (let index = 0; index < 26; index++) units.push(await assigned());
  const preview = await service.offboardingList(fixture.userId, { workflowId: fixture.workflowId }, fixture.user, bearer); assert.equal(preview.total, 26); assert.equal(preview.devices.length, 25);
  const body = { workflowId: fixture.workflowId, eligibilityRevision: fixture.eligibility, reason, confirm: true, items: preview.devices.map(unit => ({ deviceId: unit.deviceId, deviceRevision: unit.deviceRevision, assignmentId: unit.assignmentId, requestId: randomUUID() })) };
  const result = await service.request(fixture.userId, body, fixture.user, bearer); assert.ok(result.results.every(item => item.status === 'requested'));
  const second = await service.offboardingList(fixture.userId, { workflowId: fixture.workflowId, page: '2' }, fixture.user, bearer); assert.equal(second.devices.length, 1); assert.equal(second.devices[0].openRequestId, null);
  assert.equal((await service.list({}, fixture.user, bearer)).requests.length, 25); assert.equal((await service.list({ page: '2' }, fixture.user, bearer)).requests.length, 0);
});
test('ordinary direct assignment to another user remains canonical005 and derives only historical release evidence', async () => {
  const { request, unit } = await requested(); const replacement = await inventory.assign(unit.id, { userId: fixture.nextUserId }, deviceEtag(unit), fixture.user, bearer);
  const task = await service.get(request.id, fixture.user, bearer); assert.equal(task.status, 'assignment_changed'); assert.equal(task.currentDeviceRevision, '3'); assert.equal(task.closedByUserId, fixture.source.actorUserId);
  const actual = (await pool.query('SELECT action,before_assignment,after_assignment FROM device_inventory_events WHERE id=$1', [task.inventoryOperationId])).rows[0];
  assert.equal(actual.action, 'assign'); assert.equal(actual.before_assignment.id, request.assignmentId); assert.equal(actual.after_assignment.id, replacement.assignmentId);
  const before = await snapshot(); await assert.rejects(decision(task), { status: 409 }); assert.deepEqual(await snapshot(), before);
  assert.equal((await service.history(request.id, {}, fixture.user, bearer)).events.length, 1);
});
