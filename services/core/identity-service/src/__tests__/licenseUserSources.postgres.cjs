'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { Pool } = require('pg');
const { changeSource, argumentsForOperator } = require('../../scripts/license-user-source-operator');
const { provisionTenant, adoptTenant } = require('../../../../../scripts/lib/tenant-ownership-fixture.cjs');

const schema = 'license_users_' + randomUUID().replaceAll('-', '');
const migrations = path.join(__dirname, '../../migrations');
const migration = path.join(migrations, '044_license_user_sources.sql');
const tables = ['identity_license_user_sources', 'identity_license_user_source_events', 'identity_license_user_source_outbox'];
const readerSql = 'SELECT binding.*, identity_license_user_source_valid(binding) AS valid FROM identity_license_user_sources binding WHERE issuer=$1 AND client_id=$2';
const administration = new Pool({ connectionString: process.env.IDENTITY_TEST_DATABASE_URL, max: 1 });
let database;
let databaseUrl;

before(async () => {
  const files = fs.readdirSync(migrations).filter(filename => filename.endsWith('.sql')).sort();
  assert.equal(files.length, 50);
  assert.deepEqual(files.map(filename => filename.slice(0, 3)), Array.from({ length: 50 }, (_, index) => String(index + 1).padStart(3, '0')));
  await administration.query('CREATE SCHEMA ' + schema);
  const address = new URL(process.env.IDENTITY_TEST_DATABASE_URL);
  address.searchParams.set('options', '-c search_path=' + schema + ',public');
  databaseUrl = address.toString();
  process.env.DATABASE_URL = databaseUrl;
  database = require('../db');
  assert.equal(await database.initDb(), true);
  await database.query('TRUNCATE identity_tenants,users,groups,ous CASCADE');
});

after(async () => {
  await database?.pool.end();
  await administration.query('DROP SCHEMA IF EXISTS ' + schema + ' CASCADE');
  await administration.end();
});

async function fixture(overrides = {}) {
  return {
    issuer: 'https://license-source.test/' + randomUUID(),
    clientId: 'license.users~' + randomUUID(),
    tenantId: await provisionTenant(database, schema),
    clientRevision: '1',
    expectedVersion: '0',
    enabled: true,
    reason: 'Explicit offline database owner source configuration',
    ...overrides,
  };
}

async function read(input, client = database) {
  return (await client.query(readerSql, [input.issuer, input.clientId])).rows[0];
}

async function records(input) {
  return (await database.query('SELECT identity_license_user_source_event_json(event) AS event,to_jsonb(outbox) AS outbox FROM identity_license_user_source_events event JOIN identity_license_user_source_outbox outbox USING(id) WHERE issuer=$1 AND client_id=$2 ORDER BY source_version', [input.issuer, input.clientId])).rows;
}

async function privateChange(client, input) {
  return client.query('SELECT identity_license_user_source_change($1::jsonb) AS event_id', [JSON.stringify(input)]);
}

function afterChange(operation) {
  return { ...database, transaction: (callback, options) => database.transaction(async client => {
    const result = await callback(client);
    await operation(client);
    return result;
  }, options) };
}

async function temporaryTrigger(table, body, operation) {
  await database.query('CREATE FUNCTION license_source_test_hook() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN ' + body + ';END; $$;CREATE TRIGGER zzzz_license_source_test_hook BEFORE INSERT ON ' + table + ' FOR EACH ROW EXECUTE FUNCTION license_source_test_hook()');
  try { await operation(); }
  finally { await database.query('DROP TRIGGER zzzz_license_source_test_hook ON ' + table + ';DROP FUNCTION license_source_test_hook()'); }
}

test('actual main database transaction creates an exact configured source, retained event and pending outbox for an existing disabled tenant', async () => {
  const input = await fixture();
  const beforeCounts = (await database.query('SELECT (SELECT count(*) FROM identity_tenants) AS tenants,(SELECT count(*) FROM identity_tenant_ownership) AS ownership,(SELECT count(*) FROM identity_role_assignments) AS roles,(SELECT count(*) FROM users) AS users')).rows[0];
  const row = await changeSource(database, input);
  assert.equal(row.valid, true);
  assert.equal(row.tenant_id, input.tenantId);
  assert.equal(row.version, '1');
  assert.equal(row.client_revision, '1');
  assert.equal(row.enabled, true);
  assert.equal((await database.query('SELECT enabled FROM identity_tenants WHERE id=$1', [input.tenantId])).rows[0].enabled, false);
  assert.deepEqual((await database.query('SELECT (SELECT count(*) FROM identity_tenants) AS tenants,(SELECT count(*) FROM identity_tenant_ownership) AS ownership,(SELECT count(*) FROM identity_role_assignments) AS roles,(SELECT count(*) FROM users) AS users')).rows[0], beforeCounts);
  assert.deepEqual(Object.keys(row).sort(), ['id', 'issuer', 'client_id', 'tenant_id', 'client_revision', 'version', 'enabled', 'changed_at', 'event_id', 'valid'].sort());
  const [record] = await records(input);
  assert.deepEqual(record.event.review, input);
  assert.equal(record.event.before_state, null);
  assert.equal(record.event.after_state.event_id, row.event_id);
  assert.equal(record.event.after_state.version, '1');
  assert.equal(record.event.after_state.client_revision, '1');
  assert.equal(record.event.actor.databaseRole, (await database.query('SELECT session_user AS name')).rows[0].name);
  assert.equal(record.event.actor.kind, 'offline-license-user-source');
  assert.equal(record.event.correlation_id, row.event_id);
  assert.equal(record.event.type, 'license-user-source.changed');
  assert.equal(record.event.version, 1);
  assert.equal(record.outbox.status, 'pending');
  assert.equal(record.outbox.tenant_id, input.tenantId);
  assert.equal(record.outbox.type, record.event.type);
  assert.equal(record.outbox.version, record.event.version);
  assert.equal(record.outbox.correlation_id, record.event.id);
  assert.deepEqual(record.outbox.payload, record.event);
  assert.equal(Date.parse(record.outbox.created_at), Date.parse(record.event.created_at));
});

test('rotation and negative cleanup preserve the immutable binding and exact BIGINT revision strings', async () => {
  const input = await fixture({ clientRevision: '9007199254740993' });
  const first = await changeSource(database, input);
  const updated = await changeSource(database, { ...input, expectedVersion: '1', clientRevision: '9223372036854775807', enabled: false });
  assert.equal(updated.id, first.id);
  assert.equal(updated.tenant_id, first.tenant_id);
  assert.equal(updated.issuer, first.issuer);
  assert.equal(updated.client_id, first.client_id);
  assert.equal(updated.version, '2');
  assert.equal(updated.client_revision, '9223372036854775807');
  assert.equal(updated.enabled, false);
  assert.equal(updated.valid, true);
  const recorded = await records(input);
  assert.deepEqual(recorded[1].event.before_state, recorded[0].event.after_state);
  assert.equal(recorded[1].event.after_state.client_revision, '9223372036854775807');
  assert.equal(recorded[0].event.after_state.client_revision, '9007199254740993');
  const precise = (await database.query('SELECT identity_license_user_source_state_json(jsonb_populate_record(NULL::identity_license_user_sources,$1::jsonb)) AS state', [JSON.stringify({ ...recorded[0].event.after_state, version: '9007199254740993' })])).rows[0].state;
  assert.equal(precise.version, '9007199254740993');
  assert.equal(precise.client_revision, '9007199254740993');
  await assert.rejects(changeSource(database, { ...input, expectedVersion: '2', clientRevision: '9007199254740993' }), error => error.code === '23514');
});

test('selector equality and optimistic versions cannot move a binding to a different issuer, client or tenant', async () => {
  const input = await fixture();
  const original = await changeSource(database, input);
  for (const selector of [{ issuer: input.issuer + '/' }, { issuer: input.issuer.replace('https:', 'http:') }, { clientId: input.clientId.toUpperCase() }]) {
    const changed = { ...input, ...selector, expectedVersion: '1' };
    assert.equal(await read(changed), undefined);
    await assert.rejects(changeSource(database, changed), error => error.code === '40001');
  }
  await assert.rejects(changeSource(database, { ...input, tenantId: await provisionTenant(database, schema), expectedVersion: '1' }), error => error.code === '23514');
  for (const expectedVersion of ['0', '2']) await assert.rejects(changeSource(database, { ...input, expectedVersion }), error => error.code === '40001');
  assert.deepEqual(await read(input), original);
  assert.equal((await records(input)).length, 1);
});

test('simultaneous rotations serialize on the exact issuer/client and reject the stale expected version', { timeout: 15000 }, async () => {
  const input = await fixture();
  await changeSource(database, input);
  let release;
  let announce;
  let observe;
  const held = new Promise(resolve => { release = resolve; });
  const ready = new Promise(resolve => { announce = resolve; });
  const started = new Promise(resolve => { observe = resolve; });
  const first = changeSource(afterChange(async () => { announce(); await held; }), { ...input, expectedVersion: '1', clientRevision: '2' });
  await ready;
  const observed = { ...database, transaction: (callback, options) => database.transaction(async client => {
    observe((await client.query('SELECT pg_backend_pid() AS pid')).rows[0].pid);
    return callback(client);
  }, options) };
  const second = assert.rejects(changeSource(observed, { ...input, expectedVersion: '1', clientRevision: '3' }), error => error.code === '40001');
  try {
    const pid = await started;
    const until = Date.now() + 2000;
    let waiting = false;
    while (Date.now() < until) {
      waiting = (await database.query("SELECT wait_event_type='Lock' AS waiting FROM pg_stat_activity WHERE pid=$1", [pid])).rows[0]?.waiting;
      if (waiting) break;
      await new Promise(resolve => setTimeout(resolve, 10));
    }
    assert.equal(waiting, true);
  } finally { release(); }
  await first;
  await second;
  assert.equal((await read(input)).version, '2');
  assert.equal((await read(input)).client_revision, '2');
  assert.equal((await records(input)).length, 2);
});

test('database boundary enforces exact keys, canonical identifiers, bounded clients and decimal string revisions', async () => {
  const input = await fixture();
  const malformed = [null, [], {}, { ...input, extra: true }, { ...input, enabled: 'true' }, { ...input, clientRevision: 1 },
    { ...input, expectedVersion: 0 }, { ...input, clientRevision: '01' }, { ...input, expectedVersion: '-1' }, { ...input, expectedVersion: '01' },
    { ...input, clientRevision: '9223372036854775808' }, { ...input, expectedVersion: '9223372036854775807' },
    { ...input, tenantId: input.tenantId.toUpperCase() }, { ...input, tenantId: 'not-a-uuid' }, { ...input, clientId: '.' }, { ...input, clientId: '..' },
    { ...input, clientId: 'invalid/client' }, { ...input, clientId: 'x'.repeat(256) }, { ...input, issuer: input.issuer + '?query=1' },
    { ...input, issuer: input.issuer + '#fragment' }, { ...input, issuer: 'https://user:secret@example.test' }, { ...input, issuer: ' ' + input.issuer },
    { ...input, issuer: 'file:///offline' }, { ...input, reason: 'short' }, { ...input, reason: 'x'.repeat(501) }, { ...input, reason: input.reason + '\n' },
    { ...input, reason: ' ' + input.reason }, { ...input, reason: null }, { ...input, issuer: null }];
  for (const review of malformed) await assert.rejects(database.transaction(client => privateChange(client, review)), error => error.code === '23514');
  await assert.rejects(changeSource(database, { ...input, tenantId: randomUUID() }), error => error.code === '23503');
  assert.equal(await read(input), undefined);
  assert.equal((await records(input)).length, 0);
  assert.equal((await changeSource(database, { ...input, clientId: 'A'.repeat(255) })).valid, true);
});

test('configuration does not adopt or modify any unowned or foreign canonical user', async () => {
  const input = await fixture();
  const foreign = await provisionTenant(database, schema, { enabled: true });
  const owned = randomUUID();
  const unowned = randomUUID();
  await database.query('INSERT INTO users(id,username,email) VALUES($1::uuid,$1::text,$1::text),($2::uuid,$2::text,$2::text)', [owned, unowned]);
  await adoptTenant(database, schema, foreign, [{ kind: 'user', resourceId: owned }]);
  const beforeState = (await database.query('SELECT to_jsonb(account) AS account,identity_tenant_id(\'user\',id) AS owner FROM users account WHERE id=ANY($1::uuid[]) ORDER BY id', [[owned, unowned]])).rows;
  await changeSource(database, input);
  assert.deepEqual((await database.query('SELECT to_jsonb(account) AS account,identity_tenant_id(\'user\',id) AS owner FROM users account WHERE id=ANY($1::uuid[]) ORDER BY id', [[owned, unowned]])).rows, beforeState);
});

test('a second source review cannot ride the first transaction even after its scope is cleared', async () => {
  const input = await fixture();
  await assert.rejects(database.transaction(async client => {
    await privateChange(client, input);
    await client.query("SELECT set_config('opendirectory.license_user_source','',true)");
    await privateChange(client, { ...input, expectedVersion: '1', enabled: false });
  }), error => error.code === '42501');
  assert.equal(await read(input), undefined);
  assert.equal((await records(input)).length, 0);
});

test('clearing or replacing the original scope also fails the actual deferred commit', async () => {
  for (const scope of ['', '{}']) {
    const input = await fixture();
    await assert.rejects(changeSource(afterChange(client => client.query("SELECT set_config('opendirectory.license_user_source',$1,true)", [scope])), input), error => error.code === '23514');
    assert.equal(await read(input), undefined);
    assert.equal((await records(input)).length, 0);
  }
});

test('raw writes, copied evidence and populated truncations cannot substitute an original command', async () => {
  const input = await fixture();
  const row = await changeSource(database, input);
  for (const table of tables) {
    const identifier = table === tables[0] ? row.id : row.event_id;
    for (const sql of ['UPDATE ' + table + ' SET id=id WHERE id=$1', 'DELETE FROM ' + table + ' WHERE id=$1', 'INSERT INTO ' + table + ' SELECT * FROM ' + table + ' WHERE id=$1']) {
      await assert.rejects(database.query(sql, [identifier]), error => error.code === '42501');
    }
    await assert.rejects(database.query('TRUNCATE ' + table + ' CASCADE'), error => error.code === '42501');
  }
  await assert.rejects(database.transaction(async client => {
    await client.query("SELECT set_config('opendirectory.license_user_source','{}',true)");
    await client.query('UPDATE identity_license_user_sources SET enabled=false WHERE id=$1', [row.id]);
  }), error => error.code === '42501');
  assert.deepEqual(await read(input), row);
});

test('all canonical receivers reject unrelated writes after source admission with a cleared GUC', async () => {
  const userId = randomUUID();
  await database.query('INSERT INTO users(id,username,email) VALUES($1::uuid,$1::text,$1::text)', [userId]);
  for (const sql of ["UPDATE users SET title='Unrelated' WHERE id='" + userId + "'", "INSERT INTO groups(id,name) VALUES(gen_random_uuid(),'Unrelated')", 'TRUNCATE groups CASCADE', 'DELETE FROM users WHERE id=\'' + userId + '\'', "INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES('https://unrelated.test','other','" + userId + "')"]) {
    const input = await fixture();
    await assert.rejects(changeSource(afterChange(async client => {
      await client.query("SELECT set_config('opendirectory.license_user_source','',true)");
      await client.query(sql);
    }), input), error => error.code === '42501');
    assert.equal(await read(input), undefined);
    assert.equal((await records(input)).length, 0);
  }
});

test('earlier canonical inserts, updates, deletes and truncations cannot ride a later offline review', async () => {
  for (const action of ['insert', 'update', 'delete', 'truncate']) {
    const input = await fixture();
    const groupId = randomUUID();
    await database.query("INSERT INTO groups(id,name) VALUES($1,'Existing canonical group')", [groupId]);
    await assert.rejects(database.transaction(async client => {
      if (action === 'insert') await client.query("INSERT INTO groups(id,name) VALUES(gen_random_uuid(),'Mixed')");
      if (action === 'update') await client.query("UPDATE groups SET description='Mixed' WHERE id=$1", [groupId]);
      if (action === 'delete') await client.query('DELETE FROM groups WHERE id=$1', [groupId]);
      if (action === 'truncate') await client.query('TRUNCATE groups CASCADE');
      await client.query("SELECT set_config('opendirectory.license_user_source','',true)");
      await privateChange(client, input);
    }), error => error.code === '42501');
    assert.equal(await read(input), undefined);
    assert.equal((await records(input)).length, 0);
    assert.equal((await database.query('SELECT count(*)::int AS count FROM groups WHERE id=$1', [groupId])).rows[0].count, 1);
  }
});

test('every older row and truncate hook is installed and receiving fails closed when a required trigger is missing', async () => {
  const input = await fixture();
  await changeSource(database, input);
  const older = (await database.query('SELECT * FROM identity_license_user_source_hooks()')).rows;
  assert.equal(older.length, 9);
  const required = tables.flatMap(table => [
    [table, 'identity_license_user_source_guard'], [table, 'identity_license_user_source_commit'], [table, 'identity_license_user_source_no_truncate'],
    ...older.flatMap(hook => [[table, hook.trigger_name], [table, hook.trigger_name.replace(/(_no_effects|_fence)$/, '_no_truncate')]]),
  ]);
  required.push(['users', 'aaa_identity_license_user_source_fence'], ['groups', 'aaa_identity_license_user_source_no_truncate']);
  for (const [table, trigger] of required) {
    await database.query('ALTER TABLE ' + table + ' DISABLE TRIGGER ' + trigger);
    try {
      assert.equal((await read(input)).valid, false, table + ':' + trigger);
      await assert.rejects(changeSource(database, { ...input, expectedVersion: '1', enabled: false }), error => error.code === '42501');
    } finally { await database.query('ALTER TABLE ' + table + ' ENABLE TRIGGER ' + trigger); }
  }
  assert.equal((await read(input)).valid, true);
  assert.equal((await records(input)).length, 1);
});

test('older canonical fences still block source writes for their active original scopes', async () => {
  const input = await fixture();
  for (const scope of ['authority_stage', 'authority_seal', 'authority_command_checkpoint', 'authority_source_set', 'organization_mutation', 'company_registration', 'company_review', 'company_activation', 'ou_mutation']) {
    await assert.rejects(database.transaction(async client => {
      await client.query("SELECT set_config($1,'{}',true)", ['opendirectory.' + scope]);
      await privateChange(client, input);
    }));
    assert.equal(await read(input), undefined);
  }
});

test('omitted binding, event or outbox is rejected before successful physical commit', async () => {
  for (const table of tables) {
    const input = await fixture();
    await temporaryTrigger(table, 'RETURN NULL', async () => {
      await assert.rejects(database.transaction(client => privateChange(client, input)), error => ['42501', '23514'].includes(error.code));
    });
    assert.equal(await read(input), undefined);
    assert.equal((await records(input)).length, 0);
  }
});

test('late row and outbox metadata drift cannot survive deferred commit', async () => {
  const drifts = [
    [tables[0], 'NEW.client_revision=NEW.client_revision+1'], [tables[0], "NEW.changed_at=NEW.changed_at+interval '1 second'"],
    [tables[1], "NEW.created_at=NEW.created_at+interval '1 second'"], [tables[1], "NEW.actor=jsonb_build_object('databaseRole','forged')"],
    [tables[2], "NEW.type='other'"], [tables[2], 'NEW.version=NEW.version+1'], [tables[2], 'NEW.correlation_id=gen_random_uuid()'],
    [tables[2], "NEW.created_at=NEW.created_at+interval '1 second'"], [tables[2], "NEW.payload=jsonb_set(NEW.payload,'{source_version}','\"2\"'::jsonb)"],
  ];
  for (const [table, drift] of drifts) {
    const input = await fixture();
    await temporaryTrigger(table, drift + ';RETURN NEW', async () => {
      await assert.rejects(database.transaction(client => privateChange(client, input)), error => ['23514', '42501'].includes(error.code));
    });
    assert.equal(await read(input), undefined);
    assert.equal((await records(input)).length, 0);
  }
});

test('valid requires the exact actual row and retained event/outbox instead of trusting a supplied composite', async () => {
  const input = await fixture();
  const row = await changeSource(database, input);
  const original = (await records(input))[0].event.after_state;
  for (const change of [{ id: randomUUID() }, { tenant_id: randomUUID() }, { issuer: input.issuer + '/' }, { client_id: 'other' }, { client_revision: '2' }, { version: '2' }, { enabled: false }, { event_id: randomUUID() }]) {
    assert.equal((await database.query('SELECT identity_license_user_source_valid(jsonb_populate_record(NULL::identity_license_user_sources,$1::jsonb)) AS valid', [JSON.stringify({ ...original, ...change })])).rows[0].valid, false);
  }
  assert.equal(row.valid, true);
  for (const [table, mutation] of [[tables[1], 'DELETE FROM ' + tables[1] + ' WHERE id=$1'], [tables[2], 'DELETE FROM ' + tables[2] + ' WHERE id=$1'], [tables[0], "UPDATE " + tables[0] + " SET client_revision=client_revision+1 WHERE event_id=$1"]]) {
    const corrupted = await fixture();
    const saved = await changeSource(database, corrupted);
    await database.query('ALTER TABLE ' + table + ' DISABLE TRIGGER USER');
    try {
      if (table === tables[1]) {
        await database.query('ALTER TABLE identity_license_user_source_outbox DISABLE TRIGGER ALL');
        try { await database.query('DELETE FROM identity_license_user_source_outbox WHERE id=$1', [saved.event_id]); }
        finally { await database.query('ALTER TABLE identity_license_user_source_outbox ENABLE TRIGGER ALL'); }
      }
      await database.query(mutation, [saved.event_id]);
    } finally { await database.query('ALTER TABLE ' + table + ' ENABLE TRIGGER USER'); }
    assert.equal((await read(corrupted)).valid, false);
    await assert.rejects(changeSource(database, { ...corrupted, expectedVersion: '1', enabled: false }), error => error.code === '23514');
  }
});

test('physical limited SQL login, inherited owner membership and SET ROLE cannot replace the actual table owner', async () => {
  const input = await fixture();
  await changeSource(database, input);
  const role = 'license_source_limited_' + randomUUID().replaceAll('-', '');
  const owner = (await database.query('SELECT session_user AS name')).rows[0].name;
  const quotedOwner = '"' + owner.replaceAll('"', '""') + '"';
  let limited;
  try {
    await administration.query('CREATE ROLE ' + role + ' LOGIN');
    await administration.query('GRANT ' + quotedOwner + ' TO ' + role);
    await database.query('GRANT USAGE ON SCHEMA ' + schema + ' TO ' + role + ';GRANT SELECT ON identity_license_user_sources TO ' + role + ';GRANT EXECUTE ON FUNCTION identity_license_user_source_change(jsonb),identity_license_user_source_valid(identity_license_user_sources) TO ' + role);
    const address = new URL(databaseUrl);
    address.username = role;
    limited = new Pool({ connectionString: address.toString(), max: 1 });
    assert.equal((await read(input, limited)).valid, true);
    assert.equal((await limited.query('SELECT pg_has_role(session_user,$1,\'USAGE\') AS inherited', [owner])).rows[0].inherited, true);
    for (const [pool, assumed] of [[limited, null], [limited, quotedOwner], [database.pool, role]]) {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        if (assumed) await client.query('SET LOCAL ROLE ' + assumed);
        await assert.rejects(privateChange(client, { ...input, expectedVersion: '1' }), error => error.code === '42501' && error.message.includes('Actual table owner'));
      } finally { await client.query('ROLLBACK'); client.release(); }
    }
    const changedRole = await fixture();
    await assert.rejects(changeSource(afterChange(client => client.query('SET LOCAL ROLE ' + role)), changedRole), error => error.code === '42501');
    assert.equal(await read(changedRole), undefined);
  } finally {
    await limited?.end();
    await database.query('DROP OWNED BY ' + role);
    await administration.query('DROP ROLE ' + role);
  }
});

test('all new functions pin their schema and UTC and revoke PUBLIC execution', async () => {
  const functions = (await database.query("SELECT proname,proconfig,NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(proacl,acldefault('f',proowner))) permission WHERE grantee=0 AND privilege_type='EXECUTE') AS private FROM pg_proc WHERE pronamespace=$1::regnamespace AND left(proname,29)='identity_license_user_source_'", [schema])).rows;
  assert.equal(functions.length, 11);
  for (const routine of functions) {
    assert.ok(routine.proconfig.includes('search_path=' + schema + ', pg_catalog, pg_temp'), routine.proname);
    assert.ok(routine.proconfig.includes('TimeZone=UTC'), routine.proname);
    assert.equal(routine.private, true, routine.proname);
  }
});

test('migration replay and caller timezones preserve retained proof and exact configuration', async () => {
  const input = await fixture({ clientRevision: '9007199254740993' });
  const first = await changeSource(database, input);
  const saved = await records(input);
  await database.query(fs.readFileSync(migration, 'utf8'));
  await database.transaction(async client => {
    await client.query("SET LOCAL timezone='Pacific/Honolulu'");
    assert.deepEqual(await read(input, client), first);
  }, { readOnly: true });
  assert.deepEqual(await records(input), saved);
  const changed = await changeSource(afterChange(client => client.query("SET LOCAL timezone='Asia/Tokyo'")), { ...input, expectedVersion: '1', enabled: false });
  assert.equal(changed.version, '2');
  assert.equal(changed.valid, true);
  assert.deepEqual((await records(input))[1].event.before_state, saved[0].event.after_state);
});

test('CLI validates exact input and refuses implicit database fallback', async () => {
  const input = await fixture();
  const args = [input.issuer, input.clientId, input.tenantId, input.clientRevision, input.expectedVersion, 'enable', input.reason];
  assert.deepEqual(argumentsForOperator(args), input);
  assert.throws(() => argumentsForOperator([...args, 'extra']));
  assert.throws(() => argumentsForOperator([...args.slice(0, 5), 'true', input.reason]));
  const command = path.join(__dirname, '../../scripts/license-user-source-operator.js');
  const result = spawnSync(process.execPath, [command, ...args], { encoding: 'utf8', timeout: 10000, env: { ...process.env, IDENTITY_OPERATOR_DATABASE_URL: '', DATABASE_URL: databaseUrl } });
  assert.equal(result.status, 1);
  assert.equal(result.stdout, '');
  assert.match(result.stderr, /Explicit IDENTITY_OPERATOR_DATABASE_URL required/);
  assert.equal(await read(input), undefined);
});
