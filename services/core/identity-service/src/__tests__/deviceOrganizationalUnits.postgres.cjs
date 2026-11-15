'use strict';
const { test, beforeEach, afterEach, after } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const fs = require('node:fs'), path = require('node:path');
const { Pool } = require('pg');
const { activeCompany } = require('../../../../../scripts/lib/company-owner-fixture.cjs');
const { adoptTenant } = require('../../../../../scripts/lib/tenant-ownership-fixture.cjs');
const { AuthorizationState } = require('../AuthorizationState');
const { DirectoryCreator } = require('../DirectoryCreator');
const { OuMutator, ouEtag } = require('../OuMutator');
const { CompanyRoles } = require('../CompanyRoles');
const Roles = require('../CompanyRoleContract');
const { DeviceInventoryAuthority } = require('../DeviceInventoryAuthority');
const { DeviceOuAuthority } = require('../DeviceOuAuthority');
const { DeviceInventory } = require('../../../device-service/src/DeviceInventory');
const { DeviceOrganizationalUnits } = require('../../../device-service/src/DeviceOrganizationalUnits');
const C = require('../../../../../packages/device-ou-contract');
const { deviceEtag } = require('../../../../../packages/device-inventory-contract');

assert.ok(process.env.IDENTITY_TEST_DATABASE_URL);
const admin = new Pool({ connectionString: process.env.IDENTITY_TEST_DATABASE_URL, max: 1 });
const issuer = 'https://device-ou.native', bearer = 'Bearer original-device-ou-fixture';
const reason = 'Explicit original device organizational unit decision';
let schemas, identityPool, devicePool, identityDb, deviceDb, owner, creator, authority, inventoryAuthority, inventory, units, unit, ou, roles, options, late;
function storage(pool, isDevice = false) {
  return { isAvailable: () => true, query: (...args) => pool.query(...args), getClient: () => pool.connect(), async transaction(operation, settings = {}) {
    const client = await pool.connect();
    try {
      await client.query(settings.readOnly ? 'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY' : 'BEGIN');
      await client.query("SET LOCAL timezone='UTC'");
      if (settings.actor) await client.query("SELECT set_config('opendirectory.actor',$1,true)", [settings.actor]);
      const value = await operation(client); if (settings.beforeCommit) await settings.beforeCommit(client);
      if (isDevice && !settings.readOnly && late) await late(client);
      await client.query('COMMIT'); return value;
    } catch (error) { await client.query('ROLLBACK'); throw error; } finally { client.release(); }
  } };
}
beforeEach(async () => {
  schemas = ['identity_device_ou_', 'devices_ou_'].map(prefix => prefix + randomUUID().replaceAll('-', ''));
  for (const schema of schemas) await admin.query('CREATE SCHEMA ' + schema);
  identityPool = new Pool({ connectionString: process.env.IDENTITY_TEST_DATABASE_URL, max: 5, options: '-c search_path=' + schemas[0] + ',public' });
  devicePool = new Pool({ connectionString: process.env.IDENTITY_TEST_DATABASE_URL, max: 5, options: '-c search_path=' + schemas[1] + ',public' });
  identityDb = storage(identityPool); deviceDb = storage(devicePool, true); late = null;
  for (const [pool, folder] of [[identityPool, path.join(__dirname, '../../migrations')], [devicePool, path.join(__dirname, '../../../device-service/migrations')]]) {
    for (const filename of fs.readdirSync(folder).filter(name => name.endsWith('.sql')).sort()) await pool.query(fs.readFileSync(path.join(folder, filename), 'utf8'));
  }
  owner = await activeCompany(identityDb, schemas[0], issuer);
  options = { issuer, revalidate: async (_authorization, user) => (await new AuthorizationState(identityDb).state(issuer, user.sub)).tenant };
  creator = new DirectoryCreator(identityDb, options); authority = new DeviceOuAuthority(identityDb, options); inventoryAuthority = new DeviceInventoryAuthority(identityDb, options);
  inventory = new DeviceInventory(deviceDb, { authority: { read: (authorization, user, userId = null) => inventoryAuthority.read(user, authorization, userId ? { userId } : null) } });
  units = new DeviceOrganizationalUnits(deviceDb, { inventory, authority: { read: (authorization, user, ouId) => authority.resolve({ ouId }, user, authorization), units: (authorization, user, _tenant, query) => authority.units(query, user, authorization) } });
  roles = new CompanyRoles(identityDb, { revalidate: async () => {} });
  ou = await creator.ou({ name: 'Engineering devices' }, owner.user, bearer);
  unit = await inventory.create({ assetId: randomUUID(), serialNumber: randomUUID(), manufacturer: 'Native', model: 'Own device OU fixture', deviceClass: 'laptop', platform: 'linux' }, owner.user, bearer);
});
afterEach(async () => { late = null; await identityPool?.end(); await devicePool?.end(); for (const schema of schemas || []) await admin.query('DROP SCHEMA ' + schema + ' CASCADE'); });
after(() => admin.end());
const read = (user = owner.user) => units.get(unit.id, {}, user, bearer);
const tag = value => C.etag(unit.id, value.deviceRevision, value.revision);
async function intent(ouId) { if (ouId === null) return null; return (await identityPool.query("SELECT unit.id,unit.revision::text,ownership.generation::text FROM ous unit JOIN identity_tenant_ownership ownership ON ownership.resource_kind='ou' AND ownership.resource_id=unit.id WHERE unit.id=$1", [ouId])).rows[0]; }
const save = async (ouId = ou.id, previous, user = owner.user) => units.write(unit.id, { ou: await intent(ouId), reason, confirm: true }, tag(previous || await read(user)), user, bearer);
const state = async () => { const result = {}; for (const table of ['device_ou_assignments', 'device_ou_events', 'device_ou_outbox']) result[table] = (await devicePool.query('SELECT to_jsonb(row) AS value FROM ' + table + ' row ORDER BY to_jsonb(row)::text')).rows; return result; };
async function person() {
  const id = randomUUID(), subject = 'device-ou-' + id;
  await identityPool.query('INSERT INTO users(id,username,email) VALUES($1,$2,$3)', [id, subject, subject + '@test.invalid']);
  await identityPool.query('INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES($1,$2,$3)', [issuer, subject, id]);
  await adoptTenant(identityDb, schemas[0], owner.receipt.tenantId, [{ kind: 'user', resourceId: id }]);
  const source = await new AuthorizationState(identityDb).state(issuer, subject), now = Math.floor(Date.now() / 1000);
  return { id, user: { actor_type: 'user', token_use: 'access', iss: issuer, sub: subject, jti: randomUUID(), exp: now + 3600, auth_time: now, roles: source.roles, identity_authorization: source.context,
    amr: ['pwd', 'otp'], mfa_authorization: { schemaVersion: 1, userId: id, revision: '1', authTime: now, methods: ['pwd', 'otp'] } } };
}
async function grant(permissions, target) {
  const role = (await roles.create({ name: 'Own device OU duty ' + randomUUID(), description: '', permissions, maxDurationSeconds: 3600, reason, confirm: true }, owner.user, bearer)).role;
  return roles.assign(role.id, { targetType: 'user', targetId: target, scopeType: 'tenant', ouId: null, durationSeconds: 3600, reason, confirm: true }, Roles.etag('role', role), owner.user, bearer);
}

test('real own OU assignment, move and removal retain independent versions, actor, reason and pending history without changing device assignment', async () => {
  const original = await inventory.get(unit.id, owner.user, bearer), empty = await read(); assert.equal(empty.revision, '0'); assert.equal(empty.ou, null);
  const result = await save(); assert.equal(result.revision, '1'); assert.equal(result.ou.id, ou.id); assert.equal(result.updatedBy, owner.user.identity_authorization.userId); assert.equal(result.deliveryStatus, 'pending');
  const second = await creator.ou({ name: 'Sales devices' }, owner.user, bearer); assert.equal((await save(second.id)).revision, '2');
  const removed = await save(null); assert.equal(removed.revision, '3'); assert.equal(removed.ou, null);
  assert.deepEqual(await inventory.get(unit.id, owner.user, bearer), original);
  const history = await units.history(unit.id, {}, owner.user, bearer); assert.equal(history.total, 3); assert.deepEqual(history.events.map(event => event.after.ou?.id || null), [null, second.id, ou.id]);
  assert.ok(history.events.every(event => event.actorUserId === owner.user.identity_authorization.userId && event.reason === reason && event.deliveryStatus === 'pending'));
  assert.ok(history.events.every(event => event.createdAt === event.after.updatedAt && new Date(event.createdAt).toISOString() === event.createdAt));
  assert.equal(history.events[2].before, null); assert.ok(!JSON.stringify(history).includes('tokenId'));
});
test('foreign OUs, devices and selectors cannot enter the own catalog or assignment', async () => {
  const other = await activeCompany(identityDb, schemas[0], issuer); const foreign = await creator.ou({ name: 'Foreign private engineering' }, other.user, bearer);
  assert.deepEqual((await units.units({ search: 'Foreign' }, owner.user, bearer)).units, []);
  await assert.rejects(save(foreign.id), { status: 404 }); await assert.rejects(units.get(unit.id, {}, other.user, bearer), { status: 404 });
  await assert.rejects(units.units({ tenantId: other.receipt.tenantId }, owner.user, bearer), { status: 400 }); await assert.rejects(units.get(unit.id, { force: 'true' }, owner.user, bearer), { status: 400 });
  assert.equal((await read()).revision, '0');
});
test('own OU choices are server-paginated and searchable without directory profiles', async () => {
  for (let index = 0; index < 25; index++) await creator.ou({ name: 'Device unit ' + String(index).padStart(2, '0') }, owner.user, bearer);
  const first = await units.units({}, owner.user, bearer), next = await units.units({ page: '2' }, owner.user, bearer);
  assert.equal(first.total, 26); assert.equal(first.units.length, 25); assert.equal(next.units.length, 1);
  assert.equal(new Set([...first.units, ...next.units].map(row => row.id)).size, 26); assert.ok(first.units.every(C.validUnit));
  assert.equal((await units.units({ search: 'Engineering' }, owner.user, bearer)).units[0].id, ou.id);
  assert.equal((await units.units({ page: '99' }, owner.user, bearer)).units.length, 0);
});
test('inventory read and maintenance stay separate from the required own OU read duty', async () => {
  const reader = await person(); await grant(['devices.inventory.read'], reader.id);
  assert.equal((await read(reader.user)).ou, null); await assert.rejects(save(ou.id, undefined, reader.user), { status: 403 });
  const operator = await person(); await grant(['devices.inventory.read', 'devices.inventory.create'], operator.id);
  await assert.rejects(units.units({}, operator.user, bearer), { status: 403 }); await assert.rejects(save(ou.id, undefined, operator.user), { status: 403 });
  await grant(['ous.read'], operator.id); const result = await save(ou.id, undefined, operator.user); assert.equal(result.ou.id, ou.id);
  const stored = (await devicePool.query('SELECT source FROM device_ou_events WHERE id=$1', [result.operationId])).rows[0].source;
  assert.ok(stored.directoryGrant.id); assert.equal(stored.inventory.delegation.grants[0].source.targetId, operator.id); assert.deepEqual(operator.user.roles, []);
});
test('stale OU and device versions, missing confirmation and caller-supplied source are refused', async () => {
  const empty = await read(), first = await save(); await assert.rejects(save(null, empty), { status: 412 }); await assert.rejects(save(), { status: 409 });
  await assert.rejects(units.write(unit.id, { ou: null, reason, confirm: true }, undefined, owner.user, bearer), { status: 428 });
  for (const body of [{ ou: null, reason, confirm: false }, { ou: null, reason, confirm: true, source: {} }, { ou: null, reason: 'short', confirm: true }]) await assert.rejects(units.write(unit.id, body, tag(first), owner.user, bearer), { status: 400 });
  await inventory.update(unit.id, { ...Object.fromEntries(require('../../../../../packages/device-inventory-contract').DEVICE_FIELDS.map(key => [key, unit[key]])), description: 'Actual inventory change after reading OU', reason, confirm: true }, deviceEtag(unit), owner.user, bearer);
  await assert.rejects(save(null, first), { status: 412 }); assert.equal((await read()).ou.id, ou.id);
});
test('retained OU and manifest guards reject raw writes, deletion and truncation', async () => {
  await save(); for (const table of ['device_ou_assignments', 'device_ou_events', 'device_ou_outbox', 'device_ou_manifest']) {
    await assert.rejects(devicePool.query('DELETE FROM ' + table), { code: '42501' }); await assert.rejects(devicePool.query('TRUNCATE ' + table + ' CASCADE'), { code: '42501' });
  }
  await assert.rejects(devicePool.query('UPDATE device_ou_assignments SET ou=NULL'), { code: '42501' });
  await devicePool.query('ALTER TABLE device_ou_outbox DISABLE TRIGGER device_ou_guard'); await assert.rejects(read(), { status: 503 });
});
test('a selected OU revision cannot be silently replaced before admission', async () => {
  const selected = await intent(ou.id), previous = await read();
  await new OuMutator(identityDb, options).update(ou.id, { name: 'Changed after the operator selected the unit' }, ouEtag(ou), owner.user, bearer);
  await assert.rejects(units.write(unit.id, { ou: selected, reason, confirm: true }, tag(previous), owner.user, bearer), { status: 412 });
  assert.equal((await read()).revision, '0'); assert.equal((await units.units({}, owner.user, bearer)).units[0].revision, '2');
});
test('suppressed mandatory pending evidence rolls back the entire OU change', async () => {
  await devicePool.query('CREATE FUNCTION omit_device_ou() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END; $$; CREATE TRIGGER zz_omit_ou BEFORE INSERT ON device_ou_outbox FOR EACH ROW EXECUTE FUNCTION omit_device_ou()');
  const before = await state(); await assert.rejects(save(), { code: '42501' }); assert.deepEqual(await state(), before); assert.equal((await read()).revision, '0');
});
test('a late changed assignment is rejected at physical commit and leaves no acknowledged history', async () => {
  let reached = false; late = async client => {
    late = null; reached = true;
    // Privileged disposable corruption; restore normal trigger execution before COMMIT.
    await client.query("SET LOCAL session_replication_role='replica'");
    try { await client.query('UPDATE device_ou_assignments SET revision=revision+1'); }
    finally { await client.query("SET LOCAL session_replication_role='origin'"); }
  };
  const before = await state(); await assert.rejects(save(), { code: '42501' }); assert.equal(reached, true); assert.deepEqual(await state(), before);
});
test('a genuine expired original MFA deadline cannot survive the final SQL commit', async () => {
  const authTime = Math.floor(Date.now() / 1000) - 295; owner.user.auth_time = authTime; owner.user.mfa_authorization.authTime = authTime;
  let reached = false; late = async client => { late = null; reached = true; const deadline = Number((await client.query("SELECT current_setting('opendirectory.device_ou')::jsonb#>>'{source,validUntil}' AS deadline")).rows[0].deadline); await client.query('SELECT pg_sleep($1)', [Math.max(0, deadline - Date.now() / 1000) + 0.15]); };
  await assert.rejects(save(), { code: '42501' }); assert.equal(reached, true); assert.equal((await devicePool.query('SELECT count(*)::int AS count FROM device_ou_events')).rows[0].count, 0);
});
test('replacing an original OU read grant cannot rescue an in-flight device write', async () => {
  const operator = await person(); await grant(['devices.inventory.read', 'devices.inventory.create'], operator.id); const directory = await grant(['ous.read'], operator.id);
  let calls = 0; const guarded = new DeviceOrganizationalUnits(deviceDb, { inventory, authority: { read: async (authorization, user, ouId) => {
    if (++calls === 3) { await roles.revoke(directory.grant.id, { reason, confirm: true }, Roles.etag('grant', directory.grant), owner.user, bearer); await grant(['ous.read'], operator.id); }
    return authority.resolve({ ouId }, user, authorization);
  } } });
  const prior = await read(operator.user); await assert.rejects(guarded.write(unit.id, { ou: await intent(ou.id), reason, confirm: true }, tag(prior), operator.user, bearer), { status: 401 });
  assert.equal(calls, 3); assert.equal((await read()).revision, '0'); assert.equal((await units.units({}, operator.user, bearer)).total, 1);
});
test('a late OU rename or reparenting invalidates the captured original selection', async () => {
  let calls = 0; const guarded = new DeviceOrganizationalUnits(deviceDb, { inventory, authority: { read: async (authorization, user, ouId) => {
    if (++calls === 3) await new OuMutator(identityDb, options).update(ou.id, { name: 'Renamed after original selection' }, ouEtag(ou), owner.user, bearer);
    return authority.resolve({ ouId }, user, authorization);
  } } });
  await assert.rejects(guarded.write(unit.id, { ou: await intent(ou.id), reason, confirm: true }, tag(await read()), owner.user, bearer), { status: 401 }); assert.equal((await read()).revision, '0');
});
test('additive migration replay preserves original assignment, audit, outbox and private receivers', async () => {
  await save(); const before = await state(); await devicePool.query(fs.readFileSync(path.join(__dirname, '../../../device-service/migrations/013_device_organizational_units.sql'), 'utf8'));
  assert.deepEqual(await state(), before); await devicePool.query('SELECT device_ou_receiving()');
  assert.equal((await devicePool.query("SELECT count(*)::int AS count FROM device_ou_manifest")).rows[0].count, 5);
  assert.equal((await devicePool.query("SELECT has_function_privilege('public','device_ou_change(jsonb)','EXECUTE') AS allowed")).rows[0].allowed, false);
});
