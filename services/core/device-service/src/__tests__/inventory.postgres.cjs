'use strict';

const { test, before, beforeEach, afterEach, after } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { Pool } = require('pg');
const { DeviceInventory } = require('../DeviceInventory');
const { InventoryAuthority } = require('../InventoryAuthority');
const { INVENTORY_PERMISSIONS, validateDeviceValues, deviceEtag } = require('../../../../../packages/device-inventory-contract');

assert.ok(process.env.DEVICE_TEST_DATABASE_URL, 'Run scripts/test-inventory-postgres.js or set DEVICE_TEST_DATABASE_URL');

const administration = new Pool({ connectionString: process.env.DEVICE_TEST_DATABASE_URL, max: 1 });
const migrations = ['001_devices.sql', '002_device_system_info.sql', '003_device_columns_align.sql', '004_install_jobs.sql', '005_device_inventory.sql'];
const relations = ['devices', 'device_inventory_events', 'device_inventory_assignments', 'device_inventory_outbox'];
const authorization = 'Bearer inventory.explicit.server.fixture';
let schema;
let pool;
let fixture;
let database;
let inventory;
let roles;

function values(changes = {}) {
  const suffix = randomUUID();
  return { assetId: `Asset-${suffix}`, serialNumber: `Serial-${suffix}`, manufacturer: 'Native Fixture', model: 'Portable', deviceClass: 'laptop', platform: 'linux', ...changes };
}

function serverFixture() {
  const authTime = Math.floor(Date.now() / 1000);
  const user = {
    actor_type: 'user', token_use: 'access', iss: 'https://inventory.fixture.test', sub: 'explicit-native-operator',
    jti: randomUUID(), exp: authTime + 3600, auth_time: authTime,
    identity_authorization: { userId: randomUUID(), revision: '1', linkRevision: '1', rolesRevision: 'a'.repeat(64) },
  };
  const tenant = { id: randomUUID(), version: '1', generation: '1' };
  const ownUser = randomUUID();
  const nextUser = randomUUID();
  const foreignUser = randomUUID();
  const targets = new Map([
    [ownUser, { id: ownUser, tenantId: tenant.id, revision: '1', enabled: true }],
    [nextUser, { id: nextUser, tenantId: tenant.id, revision: '2', enabled: true }],
    [foreignUser, { id: foreignUser, tenantId: randomUUID(), revision: '1', enabled: true }],
  ]);
  const source = {
    schemaVersion: 1, issuer: user.iss, subject: user.sub, tokenId: user.jti, expiresAt: user.exp,
    context: structuredClone(user.identity_authorization), tenant, actorUserId: user.identity_authorization.userId,
    permissions: [...INVENTORY_PERMISSIONS], validUntil: Math.min(user.exp, authTime + 300), target: null,
  };
  const state = { user, source, targets, ownUser, nextUser, foreignUser, calls: [], transactions: [], revoked: false, beforeCheckpoint: null, beforeCommit: null };
  state.authority = new InventoryAuthority({
    endpoint: 'https://inventory.fixture.test/api/identity/device-inventory',
    fetchImpl: async (endpoint, request) => {
      assert.equal(endpoint.href, 'https://inventory.fixture.test/api/identity/device-inventory');
      assert.equal(request.headers.Authorization, authorization);
      assert.equal(request.redirect, 'error');
      assert.equal(request.cache, 'no-store');
      const targetId = request.method === 'POST' ? JSON.parse(request.body).userId : null;
      assert.equal(request.method, targetId === null ? 'GET' : 'POST');
      const target = targetId === null ? null : targets.get(targetId);
      const status = state.revoked ? 401 : targetId !== null && (!target || target.tenantId !== source.tenant.id) ? 404 : 200;
      const returned = status === 200 ? structuredClone({ ...source, target: target ? { id: target.id, revision: target.revision, enabled: target.enabled } : null }) : { error: 'Explicit server fixture rejected the original request' };
      const json = JSON.stringify(returned);
      state.calls.push({ targetId, status, json });
      return new Response(json, { status, headers: { 'content-type': 'application/json' } });
    },
  });
  return state;
}

function nativeDatabase() {
  return {
    isAvailable: () => true,
    async transaction(operation, { readOnly = false, beforeCommit } = {}) {
      const client = await pool.connect();
      const trace = { readOnly, beforeCommitRequested: typeof beforeCommit === 'function', beforeCommitRan: false, commitAttempted: false, committed: false, rolledBack: false };
      fixture.transactions.push(trace);
      try {
        await client.query(readOnly ? 'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY' : 'BEGIN');
        await client.query("SET LOCAL lock_timeout='5s'");
        await client.query("SET LOCAL statement_timeout='15s'");
        trace.pid = (await client.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
        const result = await operation(client);
        trace.operationFinished = true;
        if (!readOnly && fixture.beforeCheckpoint) await fixture.beforeCheckpoint(client, trace);
        if (beforeCommit) {
          trace.beforeCommitRan = true;
          await beforeCommit(client);
        }
        if (!readOnly && fixture.beforeCommit) await fixture.beforeCommit(client, trace);
        trace.commitAttempted = true;
        await client.query('COMMIT');
        trace.committed = true;
        return result;
      } catch (error) {
        trace.error = { code: error.code, status: error.status, message: error.message };
        await client.query('ROLLBACK');
        trace.rolledBack = true;
        throw error;
      } finally {
        client.release();
      }
    },
  };
}

async function migrate(client = pool) {
  for (const file of migrations) await client.query(fs.readFileSync(path.join(__dirname, '../../migrations', file), 'utf8'));
}

function create(body = values(), correlationId = randomUUID(), service = inventory) {
  return service.create(body, fixture.user, authorization, correlationId);
}

function assign(row, userId = fixture.ownUser, expected = deviceEtag(row), service = inventory) {
  return service.assign(row.id, { userId }, expected, fixture.user, authorization, randomUUID());
}

async function snapshot(client = pool) {
  const result = {};
  for (const relation of relations) {
    const revision = relation === 'devices' ? ', inventory_revision::text AS revision' : '';
    const rows = (await client.query(`SELECT to_jsonb(actual) AS state${revision} FROM ${relation} actual ORDER BY id`)).rows;
    result[relation] = rows.map(row => relation === 'devices' ? { ...row.state, inventory_revision: row.revision } : row.state);
  }
  return result;
}

async function emptyInventory() {
  assert.deepEqual(await snapshot(), Object.fromEntries(relations.map(relation => [relation, []])));
}

function exactSources(count, targetId = null) {
  assert.equal(fixture.calls.length, count);
  assert.ok(fixture.calls.every(call => call.status === 200 && call.targetId === targetId));
  assert.equal(new Set(fixture.calls.map(call => call.json)).size, 1);
}

async function nativeProof(action = 'create', row = null, targetId = null) {
  const source = await fixture.authority.read(authorization, fixture.user, targetId);
  const beforeState = row ? (await pool.query('SELECT device_inventory_row(actual) AS state FROM devices actual WHERE id=$1', [row.id])).rows[0].state : null;
  return { id: randomUUID(), deviceId: row?.id || randomUUID(), correlationId: randomUUID(), action, source, before: beforeState,
    values: action === 'create' ? validateDeviceValues(values()) : { userId: targetId }, assignmentId: action === 'assign' ? randomUUID() : null };
}

async function applyProof(client, proof) {
  assert.equal((await client.query('SELECT device_inventory_change($1::jsonb) AS id', [JSON.stringify(proof)])).rows[0].id, proof.id);
}

async function installTrigger(relation, body, timing = 'BEFORE INSERT') {
  await pool.query(`CREATE FUNCTION native_fixture_trigger() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN ${body} END; $$`);
  await pool.query(`CREATE TRIGGER zzz_native_fixture ${timing} ON ${relation} FOR EACH ROW EXECUTE FUNCTION native_fixture_trigger()`);
}

async function expireAtDatabase(client) {
  await client.query('SELECT pg_sleep(GREATEST(0, $1::double precision - extract(epoch FROM clock_timestamp())) + 0.05)', [fixture.source.validUntil]);
}

function shortExpiry() {
  fixture.user.exp = Math.floor(Date.now() / 1000) + 2;
  fixture.source.expiresAt = fixture.user.exp;
  fixture.source.validUntil = Math.min(fixture.user.exp, fixture.user.auth_time + 300);
}

before(async () => {
  assert.ok(Number((await administration.query('SHOW server_version_num')).rows[0].server_version_num) >= 140000);
});

beforeEach(async () => {
  schema = `device_inventory_${randomUUID().replaceAll('-', '')}`;
  roles = [];
  await administration.query(`CREATE SCHEMA ${schema}`);
  const url = new URL(process.env.DEVICE_TEST_DATABASE_URL);
  url.searchParams.set('options', `-c search_path=${schema},public -c timezone=UTC`);
  pool = new Pool({ connectionString: url.toString(), max: 8, application_name: schema });
  await migrate();
  fixture = serverFixture();
  database = nativeDatabase();
  inventory = new DeviceInventory(database, { authority: fixture.authority });
});

afterEach(async () => {
  if (pool) await pool.end();
  if (schema) await administration.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
  for (const role of roles || []) {
    await administration.query(`DROP OWNED BY ${role}`);
    await administration.query(`DROP ROLE ${role}`);
  }
});

after(async () => { await administration.end(); });

test('native create persists an unmanaged unknown not-enrolled device, exact source and pending event across connections', async () => {
  const input = values({ purchaseDate: '2024-02-29', warrantyEnd: '2027-02-28', description: 'Owned inventory' });
  const correlationId = randomUUID();
  const row = await create(input, correlationId);
  exactSources(3);
  assert.deepEqual(fixture.transactions.map(trace => [trace.beforeCommitRequested, trace.beforeCommitRan, trace.commitAttempted, trace.committed]), [[true, true, true, true]]);
  assert.equal(row.revision, '1');
  assert.equal(row.tenantId, fixture.source.tenant.id);
  assert.equal(row.managementMode, 'inventory-only');
  assert.equal(row.enrollmentStatus, 'not-enrolled');
  assert.equal(row.managementProvider, null);
  assert.equal(row.complianceStatus, 'unknown');
  assert.equal(row.lastSeen, null);
  assert.equal(row.lifecycle, 'available');
  assert.equal(row.assignedUserId, null);
  assert.equal(row.assignmentId, null);
  for (const [field, value] of Object.entries(validateDeviceValues(input))) assert.equal(row[field], value);
  const stored = await snapshot();
  const device = stored.devices[0];
  for (const field of ['last_seen', 'enrolled_at', 'is_compliant', 'agent_version', 'hostname', 'ip_address', 'kernel', 'package_manager', 'os']) assert.equal(device[field], null, field);
  assert.deepEqual(device.metadata, {});
  assert.deepEqual(device.compliance_violations, []);
  assert.equal(device.status, 'inventory-only');
  assert.equal(device.compliance_status, 'unknown');
  assert.equal(stored.device_inventory_events.length, 1);
  const event = stored.device_inventory_events[0];
  assert.equal(event.type, 'device.registered');
  assert.equal(event.version, 1);
  assert.equal(event.actor_user_id, fixture.user.identity_authorization.userId);
  assert.equal(event.correlation_id, correlationId);
  assert.equal(event.before_state, null);
  assert.deepEqual(event.proof.source, JSON.parse(fixture.calls[0].json));
  assert.deepEqual(event.after_state, device);
  assert.deepEqual(stored.device_inventory_outbox, [{ id: event.id, tenant_id: row.tenantId, status: 'pending', created_at: event.created_at }]);
  const observer = await pool.connect();
  try { assert.deepEqual(await snapshot(observer), stored); } finally { observer.release(); }
  const reopened = new DeviceInventory(nativeDatabase(), { authority: fixture.authority });
  assert.deepEqual(await reopened.get(row.id, fixture.user, authorization), row);
});

test('capabilities require the native receiver and expose exactly the inventory permissions without remote actions', async () => {
  const result = await inventory.capabilities(fixture.user, authorization);
  assert.deepEqual(result.permissions, INVENTORY_PERMISSIONS);
  assert.equal(result.tenantId, fixture.source.tenant.id);
  assert.equal(result.userId, fixture.user.identity_authorization.userId);
  assert.equal(result.managementMode, 'inventory-only');
  assert.deepEqual(result.supportedActions, []);
  exactSources(2);
  assert.equal(fixture.transactions[0].readOnly, true);
  await emptyInventory();
});

test('unavailable persistent storage cannot fall back to invented inventory', async () => {
  const unavailable = new DeviceInventory({ isAvailable: () => false }, { authority: fixture.authority });
  await assert.rejects(create(values(), randomUUID(), unavailable), { status: 503 });
  await assert.rejects(unavailable.list({}, fixture.user, authorization), { status: 503 });
  assert.equal(fixture.calls.length, 0);
  await emptyInventory();
});

test('tenant reads filter literal text and paginate deterministically without returning another tenant', async () => {
  const first = await create(values({ assetId: 'Laptop-100%_native' }));
  const second = await create(values({ assetId: 'Laptop-second' }));
  const third = await create(values({ assetId: 'Desktop-third', model: 'Stationary' }));
  const ownTenant = structuredClone(fixture.source.tenant);
  fixture.source.tenant.id = randomUUID();
  const foreign = await create(values({ assetId: 'Laptop-foreign' }));
  Object.assign(fixture.source.tenant, ownTenant);
  const list = query => inventory.list(query, fixture.user, authorization);
  const firstPage = await list({ search: 'LAPTOP', page: '1', limit: '1' });
  assert.deepEqual(firstPage.devices.map(row => row.id), [first.id]);
  assert.equal(firstPage.total, 2);
  assert.equal(firstPage.page, 1);
  assert.equal(firstPage.limit, 1);
  assert.equal(firstPage.actorUserId, fixture.user.identity_authorization.userId);
  assert.deepEqual((await list({ search: 'laptop', page: '2', limit: '1' })).devices.map(row => row.id), [second.id]);
  assert.deepEqual((await list({ search: '%_' })).devices.map(row => row.id), [first.id]);
  assert.deepEqual((await list({ search: 'Stationary' })).devices.map(row => row.id), [third.id]);
  assert.deepEqual((await list({ page: '9', limit: '2' })).devices, []);
  assert.equal((await list({})).total, 3);
  for (const id of [foreign.id, randomUUID()]) {
    await assert.rejects(inventory.get(id, fixture.user, authorization), { status: 404 });
    await assert.rejects(inventory.history(id, {}, fixture.user, authorization), { status: 404 });
    await assert.rejects(inventory.assign(id, { userId: fixture.ownUser }, deviceEtag(first), fixture.user, authorization), { status: 404 });
  }
});

test('caller tenant selectors, malformed pages and noncanonical history selectors are rejected', async () => {
  const row = await create();
  const beforeState = await snapshot();
  for (const query of [{ tenantId: randomUUID() }, { page: '0' }, { limit: '101' }, { page: 1 }, { page: '01' }, { search: '\u0000' }]) {
    await assert.rejects(inventory.list(query, fixture.user, authorization), { status: 400 });
  }
  await assert.rejects(inventory.history(row.id, { search: 'forged' }, fixture.user, authorization), { status: 400 });
  assert.deepEqual(await snapshot(), beforeState);
});

test('foreign caller identity and foreign or missing actual recipient cannot acquire authority', async () => {
  const row = await create();
  const beforeState = await snapshot();
  const foreignActor = structuredClone(fixture.user);
  foreignActor.identity_authorization.userId = fixture.foreignUser;
  await assert.rejects(inventory.get(row.id, foreignActor, authorization), { status: 503 });
  const foreignSubject = { ...fixture.user, sub: 'foreign-operator' };
  await assert.rejects(inventory.list({}, foreignSubject, authorization), { status: 503 });
  for (const recipient of [fixture.foreignUser, randomUUID()]) await assert.rejects(assign(row, recipient), { status: 404 });
  assert.deepEqual(await snapshot(), beforeState);
});

test('assignment, exclusive reassignment and release retain old links and exact paginated history', async () => {
  const row = await create();
  fixture.calls = [];
  const first = await assign(row);
  exactSources(3, fixture.ownUser);
  assert.equal(first.revision, '2');
  assert.equal(first.assignedUserId, fixture.ownUser);
  assert.equal(first.lifecycle, 'assigned');
  assert.ok(first.assignmentId);
  const second = await assign(first, fixture.nextUser);
  assert.equal(second.revision, '3');
  assert.notEqual(second.assignmentId, first.assignmentId);
  const links = (await snapshot()).device_inventory_assignments;
  assert.equal(links.length, 2);
  assert.deepEqual(links.filter(link => link.released_at === null).map(link => link.id), [second.assignmentId]);
  const previous = links.find(link => link.id === first.assignmentId);
  assert.ok(previous.released_at);
  assert.ok(previous.released_by_command_id);
  assert.deepEqual(previous.target_snapshot, { id: fixture.ownUser, revision: '1', enabled: true });
  const released = await assign(second, null);
  assert.equal(released.revision, '4');
  assert.equal(released.assignedUserId, null);
  assert.equal(released.assignmentId, null);
  assert.equal(released.lifecycle, 'available');
  const stored = await snapshot();
  assert.equal(stored.device_inventory_assignments.length, 2);
  assert.ok(stored.device_inventory_assignments.every(link => link.released_at && link.released_by_command_id));
  assert.equal(stored.device_inventory_events.length, 4);
  assert.equal(stored.device_inventory_outbox.length, 4);
  const history = await inventory.history(row.id, {}, fixture.user, authorization);
  assert.equal(history.total, 4);
  assert.deepEqual(history.events.map(event => event.type), ['device.assignment.released', 'device.assigned', 'device.assigned', 'device.registered']);
  assert.deepEqual(history.events.map(event => event.after.revision), ['4', '3', '2', '1']);
  assert.deepEqual(history.events.map(event => event.before?.revision || null), ['3', '2', '1', null]);
  assert.ok(history.events.every(event => event.version === 1 && event.deliveryStatus === 'pending' && event.actorUserId === fixture.user.identity_authorization.userId && event.tenantId === row.tenantId));
  const page = await inventory.history(row.id, { page: '2', limit: '2' }, fixture.user, authorization);
  assert.equal(page.total, 4);
  assert.deepEqual(page.events, history.events.slice(2));
  assert.deepEqual(await inventory.get(row.id, fixture.user, authorization), released);
});

test('duplicate assignments and duplicate releases cannot advance revisions or append history', async () => {
  const row = await create();
  const initial = await snapshot();
  await assert.rejects(assign(row, null), { status: 409 });
  assert.deepEqual(await snapshot(), initial);
  const assigned = await assign(row);
  const beforeState = await snapshot();
  await assert.rejects(assign(assigned), { status: 409 });
  assert.deepEqual(await snapshot(), beforeState);
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM device_inventory_assignments WHERE released_at IS NULL')).rows[0].count, 1);
});

test('missing, malformed, wrong-device and stale ETags cannot write another version', async () => {
  const row = await create();
  for (const expected of [undefined, null, '']) await assert.rejects(inventory.assign(row.id, { userId: fixture.ownUser }, expected, fixture.user, authorization), { status: 428 });
  for (const expected of ['*', `W/${deviceEtag(row)}`, `${deviceEtag(row)}, ${deviceEtag(row)}`]) await assert.rejects(inventory.assign(row.id, { userId: fixture.ownUser }, expected, fixture.user, authorization), { status: 400 });
  await assert.rejects(assign(row, fixture.ownUser, deviceEtag({ id: randomUUID(), revision: '1' })), { status: 412 });
  const assigned = await assign(row);
  const beforeState = await snapshot();
  await assert.rejects(assign(row, fixture.nextUser), { status: 412 });
  assert.deepEqual(await snapshot(), beforeState);
  assert.equal((await inventory.get(row.id, fixture.user, authorization)).revision, assigned.revision);
});

for (const field of ['assetId', 'serialNumber']) {
  test(`native ${field} uniqueness is tenant-local and case-insensitive`, async () => {
    const input = values();
    await create(input);
    const beforeState = await snapshot();
    await assert.rejects(create(values({ [field]: input[field].toUpperCase() })), { code: '23505' });
    assert.deepEqual(await snapshot(), beforeState);
    fixture.source.tenant.id = randomUUID();
    const foreign = await create({ ...input, [field]: input[field].toUpperCase() });
    assert.equal(foreign.tenantId, fixture.source.tenant.id);
    assert.equal((await snapshot()).devices.length, 2);
  });
}

for (const action of ['create', 'assign', 'release']) {
  test(`original source revoked at the final ${action} checkpoint rolls back actual DML and retained evidence`, async () => {
    let row = action === 'create' ? null : await create();
    if (action === 'release') row = await assign(row);
    const beforeState = await snapshot();
    fixture.calls = [];
    fixture.beforeCheckpoint = async client => {
      assert.equal((await client.query('SELECT count(*)::int AS count FROM device_inventory_events')).rows[0].count, beforeState.device_inventory_events.length + 1);
      assert.equal((await client.query('SELECT count(*)::int AS count FROM device_inventory_outbox')).rows[0].count, beforeState.device_inventory_outbox.length + 1);
      fixture.revoked = true;
    };
    await assert.rejects(action === 'create' ? create() : assign(row, action === 'release' ? null : fixture.ownUser), { status: 401 });
    assert.deepEqual(fixture.calls.map(call => call.status), [200, 200, 401]);
    assert.equal(fixture.calls[0].json, fixture.calls[1].json);
    const trace = fixture.transactions.at(-1);
    assert.equal(trace.operationFinished, true);
    assert.equal(trace.beforeCommitRequested, true);
    assert.equal(trace.beforeCommitRan, true);
    assert.equal(trace.commitAttempted, false);
    assert.equal(trace.rolledBack, true);
    assert.deepEqual(await snapshot(), beforeState);
  });
}

test('actual source expiry before the service final checkpoint rolls back the native create', async () => {
  shortExpiry();
  fixture.beforeCheckpoint = expireAtDatabase;
  await assert.rejects(create(), { status: 503 });
  exactSources(3);
  assert.equal(fixture.transactions.at(-1).beforeCommitRan, true);
  assert.equal(fixture.transactions.at(-1).commitAttempted, false);
  await emptyInventory();
});

test('actual expiry after the final service checkpoint is rejected by the physical deferred COMMIT', async () => {
  shortExpiry();
  fixture.beforeCommit = async (client, trace) => {
    assert.equal(trace.beforeCommitRan, true);
    assert.equal((await client.query('SELECT count(*)::int AS count FROM devices')).rows[0].count, 1);
    await expireAtDatabase(client);
  };
  await assert.rejects(create(), { code: '42501' });
  exactSources(3);
  const trace = fixture.transactions.at(-1);
  assert.equal(trace.operationFinished, true);
  assert.equal(trace.beforeCommitRan, true);
  assert.equal(trace.commitAttempted, true);
  assert.equal(trace.rolledBack, true);
  await emptyInventory();
});

for (const drift of ['revision', 'enabled', 'removed', 'tenant']) {
  test(`actual recipient ${drift} changes before the final checkpoint roll back assignment`, async () => {
    const row = await create();
    const beforeState = await snapshot();
    fixture.calls = [];
    fixture.beforeCheckpoint = async client => {
      assert.equal((await client.query('SELECT count(*)::int AS count FROM device_inventory_assignments WHERE released_at IS NULL')).rows[0].count, 1);
      const target = fixture.targets.get(fixture.ownUser);
      if (drift === 'removed') fixture.targets.delete(fixture.ownUser);
      else if (drift === 'tenant') target.tenantId = fixture.targets.get(fixture.foreignUser).tenantId;
      else if (drift === 'enabled') target.enabled = false;
      else target.revision = '2';
    };
    await assert.rejects(assign(row), { status: ['removed', 'tenant'].includes(drift) ? 404 : 401 });
    assert.equal(fixture.calls.length, 3);
    assert.equal(fixture.calls[0].json, fixture.calls[1].json);
    assert.notEqual(fixture.calls[1].json, fixture.calls[2].json);
    assert.equal(fixture.transactions.at(-1).beforeCommitRan, true);
    assert.deepEqual(await snapshot(), beforeState);
  });
}

test('an otherwise valid changed tenant generation cannot replace the original exact source', async () => {
  fixture.beforeCheckpoint = async () => { fixture.source.tenant.generation = '2'; };
  await assert.rejects(create(), { status: 401 });
  assert.equal(fixture.calls.length, 3);
  assert.equal(fixture.calls[0].json, fixture.calls[1].json);
  assert.notEqual(fixture.calls[1].json, fixture.calls[2].json);
  await emptyInventory();
});

for (const relation of relations) {
  for (const trigger of ['device_inventory_guard', 'device_inventory_truncate']) {
    test(`removing ${relation}.${trigger} makes the native receiver fail closed`, async () => {
      const row = await create();
      const beforeState = await snapshot();
      await pool.query(`DROP TRIGGER ${trigger} ON ${relation}`);
      await assert.rejects(create(), { status: 503 });
      await assert.rejects(inventory.capabilities(fixture.user, authorization), { status: 503 });
      await assert.rejects(inventory.list({}, fixture.user, authorization), { status: 503 });
      await assert.rejects(inventory.get(row.id, fixture.user, authorization), { status: 503 });
      await assert.rejects(inventory.history(row.id, {}, fixture.user, authorization), { status: 503 });
      assert.deepEqual(await snapshot(), beforeState);
    });
  }
}

test('a missing deferred event receiver prevents acknowledged service writes and reads', async () => {
  await pool.query('DROP TRIGGER device_inventory_commit ON device_inventory_events');
  await assert.rejects(create(), { status: 503 });
  await assert.rejects(inventory.capabilities(fixture.user, authorization), { status: 503 });
  await emptyInventory();
});

test('removing a device row guard after the service checkpoint is rejected at physical COMMIT', async () => {
  fixture.beforeCommit = async client => { await client.query('DROP TRIGGER device_inventory_guard ON devices'); };
  await assert.rejects(create(), { code: '42501' });
  exactSources(3);
  assert.equal(fixture.transactions.at(-1).commitAttempted, true);
  await emptyInventory();
  await pool.query('SELECT device_inventory_receiving()');
});

for (const relation of ['device_inventory_events', 'device_inventory_outbox', 'devices']) {
  test(`omitting the actual ${relation} insertion cannot produce a successful service response`, async () => {
    await installTrigger(relation, 'RETURN NULL;');
    await assert.rejects(create(), error => ['42501', '23514', '23503'].includes(error.code) || [404, 503].includes(error.status));
    assert.equal(fixture.transactions.at(-1).committed, false);
    assert.equal(fixture.transactions.at(-1).rolledBack, true);
    await emptyInventory();
  });
}

for (const relation of ['device_inventory_outbox', 'devices', 'device_inventory_assignments']) {
  test(`a native change with omitted ${relation} reaches deferred COMMIT and must roll back`, async () => {
    const row = relation === 'device_inventory_assignments' ? await create() : null;
    const beforeState = await snapshot();
    const proof = await nativeProof(row ? 'assign' : 'create', row, row ? fixture.ownUser : null);
    await installTrigger(relation, 'RETURN NULL;');
    await assert.rejects(database.transaction(client => applyProof(client, proof)), { code: relation === 'devices' ? '23503' : '23514' });
    const trace = fixture.transactions.at(-1);
    assert.equal(trace.operationFinished, true);
    assert.equal(trace.commitAttempted, true);
    assert.equal(trace.committed, false);
    assert.equal(trace.rolledBack, true);
    assert.deepEqual(await snapshot(), beforeState);
  });
}

test('a late BEFORE trigger changing the real device after the row guard fails deferred COMMIT', async () => {
  await installTrigger('devices', "NEW.description='Actual late trigger drift'; RETURN NEW;");
  fixture.beforeCommit = async client => {
    assert.equal((await client.query('SELECT description FROM devices')).rows[0].description, 'Actual late trigger drift');
  };
  await assert.rejects(create(), { code: '23514' });
  exactSources(3);
  assert.equal(fixture.transactions.at(-1).beforeCommitRan, true);
  assert.equal(fixture.transactions.at(-1).commitAttempted, true);
  await emptyInventory();
});

test('a late assignment target snapshot drift fails deferred COMMIT after service validation', async () => {
  const row = await create();
  const beforeState = await snapshot();
  await installTrigger('device_inventory_assignments', "NEW.target_snapshot=jsonb_set(NEW.target_snapshot,'{revision}','\"99\"'::jsonb); RETURN NEW;");
  await assert.rejects(assign(row), { code: '23514' });
  assert.equal(fixture.transactions.at(-1).beforeCommitRan, true);
  assert.equal(fixture.transactions.at(-1).commitAttempted, true);
  assert.deepEqual(await snapshot(), beforeState);
});

test('removing the actual outbox after service receipt validation fails physical COMMIT', async () => {
  fixture.beforeCommit = async client => {
    await client.query('ALTER TABLE device_inventory_outbox DISABLE TRIGGER device_inventory_guard');
    assert.equal((await client.query('DELETE FROM device_inventory_outbox')).rowCount, 1);
    await client.query('ALTER TABLE device_inventory_outbox ENABLE TRIGGER device_inventory_guard');
    await client.query('SELECT device_inventory_receiving()');
  };
  await assert.rejects(create(), { code: '23514' });
  exactSources(3);
  assert.equal(fixture.transactions.at(-1).beforeCommitRan, true);
  assert.equal(fixture.transactions.at(-1).commitAttempted, true);
  await emptyInventory();
});

test('raw owner writes cannot invent devices, change telemetry, edit retained history or forge receipt rows', async () => {
  const row = await assign(await create());
  const beforeState = await snapshot();
  const statements = [
    ['INSERT INTO devices(id,tenant_id,name) VALUES($1,$2,\'Raw device\')', [randomUUID(), row.tenantId]],
    ['UPDATE devices SET inventory_revision=99 WHERE id=$1', [row.id]],
    ["UPDATE devices SET is_compliant=true,last_seen=clock_timestamp(),enrolled_at=clock_timestamp(),status='active' WHERE id=$1", [row.id]],
    ['UPDATE devices SET tenant_id=$2 WHERE id=$1', [row.id, randomUUID()]],
    ['DELETE FROM devices WHERE id=$1', [row.id]],
    ["UPDATE device_inventory_assignments SET target_snapshot='{}'::jsonb", []],
    ['DELETE FROM device_inventory_assignments', []],
    ['UPDATE device_inventory_events SET version=2', []],
    ['DELETE FROM device_inventory_events', []],
    ["UPDATE device_inventory_outbox SET status='pending'", []],
    ['DELETE FROM device_inventory_outbox', []],
    ['INSERT INTO device_inventory_events SELECT * FROM device_inventory_events LIMIT 1', []],
    ['INSERT INTO device_inventory_outbox SELECT * FROM device_inventory_outbox LIMIT 1', []],
    ['INSERT INTO device_inventory_assignments SELECT * FROM device_inventory_assignments LIMIT 1', []],
  ];
  for (const [sql, parameters] of statements) {
    await assert.rejects(pool.query(sql, parameters), { code: '42501' });
    assert.deepEqual(await snapshot(), beforeState);
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query("SELECT set_config('opendirectory.device_inventory',$1,true)", [beforeState.device_inventory_events[0].id]);
    await assert.rejects(client.query('UPDATE devices SET inventory_revision=100 WHERE id=$1', [row.id]), { code: '42501' });
  } finally {
    await client.query('ROLLBACK');
    client.release();
  }
  assert.deepEqual(await snapshot(), beforeState);
});

for (const relation of relations) {
  test(`TRUNCATE ${relation} CASCADE cannot discard devices or retained inventory evidence`, async () => {
    await assign(await create());
    const beforeState = await snapshot();
    await assert.rejects(pool.query(`TRUNCATE ${relation} CASCADE`), { code: '42501' });
    assert.deepEqual(await snapshot(), beforeState);
  });
}

test('a SQL-limited login cannot execute owner inventory transitions even with explicit function and table grants', async () => {
  const role = `inventory_limited_${randomUUID().replaceAll('-', '')}`;
  const password = randomUUID();
  await administration.query(`CREATE ROLE ${role} LOGIN PASSWORD '${password}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT`);
  roles.push(role);
  await administration.query(`GRANT USAGE ON SCHEMA ${schema} TO ${role}`);
  await pool.query(`GRANT SELECT,INSERT,UPDATE,DELETE,TRUNCATE ON ALL TABLES IN SCHEMA ${schema} TO ${role}`);
  await pool.query(`GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA ${schema} TO ${role}`);
  const proof = await nativeProof();
  const url = new URL(process.env.DEVICE_TEST_DATABASE_URL);
  url.username = role;
  url.password = password;
  url.searchParams.set('options', `-c search_path=${schema},public`);
  const limited = new Pool({ connectionString: url.toString(), max: 1 });
  try {
    const identity = (await limited.query('SELECT session_user,current_user')).rows[0];
    assert.equal(identity.session_user, role);
    assert.equal(identity.current_user, role);
    await assert.rejects(limited.query('SELECT device_inventory_change($1::jsonb)', [JSON.stringify(proof)]), { code: '42501' });
    await assert.rejects(limited.query('INSERT INTO devices(id,tenant_id) VALUES($1,$2)', [proof.deviceId, proof.source.tenant.id]), { code: '42501' });
    await assert.rejects(limited.query('TRUNCATE devices CASCADE'), { code: '42501' });
    const event = {
      id: proof.id, tenant_id: proof.source.tenant.id, device_id: proof.deviceId, action: 'create', type: 'device.registered', version: 1,
      correlation_id: proof.correlationId, actor_user_id: proof.source.actorUserId, proof, after_state: {},
      created_at: new Date().toISOString(), valid_until: new Date(proof.source.validUntil * 1000).toISOString(),
    };
    const client = await limited.connect();
    try {
      await client.query('BEGIN');
      event.transaction_id = (await client.query('SELECT txid_current() AS id')).rows[0].id;
      await client.query("SELECT set_config('opendirectory.device_inventory',$1,true)", [event.id]);
      await assert.rejects(client.query('INSERT INTO device_inventory_events SELECT (jsonb_populate_record(NULL::device_inventory_events,$1::jsonb)).*', [JSON.stringify(event)]), { code: '42501' });
    } finally {
      await client.query('ROLLBACK');
      client.release();
    }
  } finally {
    await limited.end();
  }
  await emptyInventory();
});

test('SET ROLE to the actual owner cannot bypass the explicit assumed-role inventory fence', async () => {
  const proof = await nativeProof();
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const owner = (await client.query("SELECT pg_get_userbyid(relowner) AS name FROM pg_class WHERE oid='devices'::regclass")).rows[0].name;
    await client.query(`SET LOCAL ROLE "${owner.replaceAll('"', '""')}"`);
    assert.equal((await client.query("SELECT current_setting('role') AS role")).rows[0].role, owner);
    await assert.rejects(applyProof(client, proof), { code: '42501' });
  } finally {
    await client.query('ROLLBACK');
    client.release();
  }
  await emptyInventory();
  const eventClient = await pool.connect();
  try {
    await eventClient.query('BEGIN');
    const owner = (await eventClient.query('SELECT session_user AS name')).rows[0].name;
    await eventClient.query(`SET LOCAL ROLE "${owner.replaceAll('"', '""')}"`);
    await eventClient.query("SELECT set_config('opendirectory.device_inventory',$1,true)", [proof.id]);
    const event = {
      id: proof.id, tenant_id: proof.source.tenant.id, device_id: proof.deviceId, action: 'create', type: 'device.registered', version: 1,
      correlation_id: proof.correlationId, actor_user_id: proof.source.actorUserId, proof, after_state: {},
      created_at: new Date().toISOString(), valid_until: new Date(proof.source.validUntil * 1000).toISOString(),
      transaction_id: (await eventClient.query('SELECT txid_current() AS id')).rows[0].id,
    };
    await assert.rejects(eventClient.query('INSERT INTO device_inventory_events SELECT (jsonb_populate_record(NULL::device_inventory_events,$1::jsonb)).*', [JSON.stringify(event)]), { code: '42501' });
  } finally {
    await eventClient.query('ROLLBACK');
    eventClient.release();
  }
  await emptyInventory();
});

test('all migrations replay without deleting fixtures, resetting revisions or duplicating retained history', async () => {
  const assigned = await assign(await create(values({ purchaseDate: '2024-02-29', warrantyEnd: '2028-02-29' })));
  await assign(assigned, fixture.nextUser);
  const beforeState = await snapshot();
  const history = await inventory.history(assigned.id, {}, fixture.user, authorization);
  await migrate();
  await migrate();
  assert.deepEqual(await snapshot(), beforeState);
  assert.deepEqual(await inventory.history(assigned.id, {}, fixture.user, authorization), history);
  assert.equal((await inventory.get(assigned.id, fixture.user, authorization)).revision, '3');
  await pool.query('SELECT device_inventory_receiving()');
});

test('non-UTC database sessions normalize real row, proof and assignment timestamps consistently', async () => {
  const url = new URL(process.env.DEVICE_TEST_DATABASE_URL);
  url.searchParams.set('options', `-c search_path=${schema},public -c timezone=Pacific/Honolulu`);
  const localPool = new Pool({ connectionString: url.toString(), max: 1 });
  const utcPool = pool;
  try {
    pool = localPool;
    const row = await create(values({ purchaseDate: '2024-02-29', warrantyEnd: '2028-02-29' }));
    const assigned = await assign(row);
    assert.equal((await localPool.query('SHOW timezone')).rows[0].TimeZone, 'Pacific/Honolulu');
    const localState = await snapshot(localPool);
    const utcState = await snapshot(utcPool);
    assert.deepEqual(localState.device_inventory_events.map(event => event.after_state), utcState.device_inventory_events.map(event => event.after_state));
    assert.deepEqual(await inventory.get(row.id, fixture.user, authorization), assigned);
    pool = utcPool;
    assert.deepEqual(await inventory.get(row.id, fixture.user, authorization), assigned);
    assert.equal(assigned.purchaseDate, '2024-02-29');
    assert.equal(assigned.warrantyEnd, '2028-02-29');
    assert.equal((await snapshot()).device_inventory_assignments.length, 1);
  } finally {
    pool = utcPool;
    await localPool.end();
  }
});

test('observed concurrent same-ETag writers block on the real row lock and the second receives 412', async () => {
  const row = await create();
  const beforeState = await snapshot();
  let lockedResolve;
  let releaseResolve;
  const locked = new Promise(resolve => { lockedResolve = resolve; });
  const release = new Promise(resolve => { releaseResolve = resolve; });
  let firstPid;
  fixture.beforeCommit = async (client, trace) => {
    firstPid = trace.pid;
    lockedResolve();
    await release;
  };
  const first = assign(row);
  first.catch(() => {});
  let second;
  try {
    await Promise.race([locked, first.then(() => assert.fail('First writer must pause at beforeCommit'))]);
    second = assign(row, fixture.nextUser);
    second.catch(() => {});
    let waiting;
    const deadline = Date.now() + 4000;
    while (Date.now() < deadline) {
      waiting = (await pool.query("SELECT pid,pg_blocking_pids(pid) AS blockers FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock' AND query LIKE 'SELECT device_inventory_row%FOR UPDATE' AND $2::int=ANY(pg_blocking_pids(pid))", [schema, firstPid])).rows[0];
      if (waiting) break;
      await new Promise(resolve => setTimeout(resolve, 10));
    }
    assert.ok(waiting, 'The second actual PostgreSQL writer must be observed waiting on the first transaction');
    assert.notEqual(waiting.pid, firstPid);
    assert.ok(waiting.blockers.includes(firstPid));
    assert.deepEqual(await snapshot(), beforeState);
    releaseResolve();
    const winner = await first;
    await assert.rejects(second, { status: 412 });
    assert.equal(winner.revision, '2');
    assert.equal(winner.assignedUserId, fixture.ownUser);
    const stored = await snapshot();
    assert.equal(stored.device_inventory_events.length, 2);
    assert.equal(stored.device_inventory_outbox.length, 2);
    assert.equal(stored.device_inventory_assignments.length, 1);
    assert.equal(stored.devices[0].inventory_revision, '2');
    assert.equal(stored.devices[0].assigned_user, fixture.ownUser);
    assert.equal(fixture.transactions.filter(trace => !trace.readOnly && trace.committed).length, 2);
    assert.equal(fixture.transactions.filter(trace => trace.error?.status === 412 && trace.rolledBack).length, 1);
  } finally {
    releaseResolve();
    await Promise.allSettled([first, second]);
  }
});

for (const [importedRevision, nextRevision] of [
  ['9007199254740993', '9007199254740994'],
  ['9223372036854775806', '9223372036854775807'],
]) {
  test(`explicit privileged fixture import of BIGINT ${importedRevision} preserves exact read ETags and assignment revision ${nextRevision}`, async () => {
    const created = await create();
    const creationState = await snapshot();
    await database.transaction(async client => {
      await client.query('ALTER TABLE devices DISABLE TRIGGER device_inventory_guard');
      assert.equal((await client.query('UPDATE devices SET inventory_revision=$2::bigint WHERE id=$1 AND tenant_id=$3', [created.id, importedRevision, created.tenantId])).rowCount, 1);
      await client.query('ALTER TABLE devices ENABLE TRIGGER device_inventory_guard');
      await client.query('SELECT device_inventory_receiving()');
    });
    const importedState = await snapshot();
    assert.deepEqual(importedState, { ...creationState, devices: [{ ...creationState.devices[0], inventory_revision: importedRevision }] });
    const current = await inventory.get(created.id, fixture.user, authorization);
    assert.equal(current.revision, importedRevision);
    const expected = `"device-${created.id}-${importedRevision}"`;
    assert.equal(deviceEtag(current), expected);
    const listed = await inventory.list({}, fixture.user, authorization);
    assert.equal(listed.devices[0].revision, importedRevision);
    assert.equal(deviceEtag(listed.devices[0]), expected);
    const observed = (await pool.query('SELECT to_jsonb(actual) AS state, inventory_revision::text AS revision, device_inventory_row(actual) AS canonical FROM devices actual WHERE id=$1', [created.id])).rows[0];
    assert.equal(observed.revision, importedRevision);
    assert.deepEqual(observed.canonical, { ...observed.state, inventory_revision: observed.revision });
    assert.equal(typeof observed.canonical.inventory_revision, 'string');
    fixture.calls = [];
    const assigned = await assign(current, fixture.ownUser, expected);
    exactSources(3, fixture.ownUser);
    assert.equal(assigned.revision, nextRevision);
    assert.equal(deviceEtag(assigned), `"device-${created.id}-${nextRevision}"`);
    assert.equal((await pool.query('SELECT inventory_revision::text AS revision FROM devices WHERE id=$1', [created.id])).rows[0].revision, nextRevision);
    assert.deepEqual(await inventory.get(created.id, fixture.user, authorization), assigned);
    const assignedState = await snapshot();
    assert.equal(assignedState.devices[0].inventory_revision, nextRevision);
    assert.equal(assignedState.device_inventory_events.length, 2);
    assert.equal(assignedState.device_inventory_outbox.length, 2);
    assert.equal(assignedState.device_inventory_assignments.length, 1);
    const assignmentEvent = assignedState.device_inventory_events.find(event => event.type === 'device.assigned');
    assert.equal(assignmentEvent.before_state.inventory_revision, importedRevision);
    assert.equal(assignmentEvent.proof.before.inventory_revision, importedRevision);
    assert.equal(assignmentEvent.after_state.inventory_revision, nextRevision);
    assert.deepEqual(assignmentEvent.after_state, assignedState.devices[0]);
    const history = await inventory.history(created.id, {}, fixture.user, authorization);
    assert.deepEqual(history.events.map(event => event.after.revision), [nextRevision, '1']);
    assert.equal(history.events[0].before.revision, importedRevision);
    if (nextRevision === '9223372036854775807') {
      await assert.rejects(assign(assigned, fixture.nextUser, deviceEtag(assigned)), { code: '22003' });
      const trace = fixture.transactions.at(-1);
      assert.equal(trace.rolledBack, true);
      assert.equal(trace.committed, false);
      assert.equal(trace.commitAttempted, false);
      assert.deepEqual(await snapshot(), assignedState);
      assert.equal((await pool.query('SELECT inventory_revision::text AS revision FROM devices WHERE id=$1', [created.id])).rows[0].revision, nextRevision);
      assert.deepEqual(await inventory.get(created.id, fixture.user, authorization), assigned);
      assert.deepEqual(await inventory.history(created.id, {}, fixture.user, authorization), history);
    }
  });
}
