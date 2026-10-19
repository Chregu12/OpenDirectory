'use strict';

const { test, before, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { Pool } = require('pg');
const { PolicyConfiguration, etag, context } = require('../PolicyConfiguration');
const { publicationTag } = require('../PolicyPublication');

const schema = 'blueprint_preview_' + randomUUID().replaceAll('-', '');
const administration = new Pool({ connectionString: process.env.LICENSE_TEST_DATABASE_URL, max: 1 });
const migrations = ['001_policies.sql', '003_blueprints.sql', '018_policy_configuration.sql', '019_policy_publication.sql'];
const tables = ['blueprints', 'blueprint_configurations', 'blueprint_assignments', 'policies', 'policy_assignments', 'policy_links',
  'policy_configuration_origins', 'policy_configuration_audit', 'policy_configuration_outbox', 'policy_publication_heads',
  'policy_publications', 'policy_publication_audit', 'policy_publication_outbox'];
const actorId = randomUUID();
const reviewerId = randomUUID();
const bearer = 'Bearer owned.blueprint.preview';
const confirmation = { reason: 'Explicit owned blueprint preview fixture', acknowledgeScope: true };
let pool;
let store;
let state;

function actor(roles = ['policy-administrator'], userId = actorId) {
  const authTime = Math.floor(Date.now() / 1000);
  return { actor_type: 'user', token_use: 'access', iss: 'https://blueprint-preview.test', sub: 'owned-' + userId,
    client_id: 'owned-preview-client', jti: randomUUID(), exp: authTime + 3600, iat: authTime, roles,
    identity_authorization: { userId, revision: '1', linkRevision: '1', rolesRevision: 'a'.repeat(64) },
    auth_time: authTime, amr: ['pwd', 'otp'], mfa_authorization: { schemaVersion: 1, userId, revision: '1', authTime, methods: ['pwd', 'otp'] } };
}
function database(connectionPool) {
  return { getClient: () => connectionPool.connect(), query: (...args) => connectionPool.query(...args) };
}
function makeStore(connectionPool) {
  return new PolicyConfiguration(database(connectionPool), {
    authority: async (authorization, user) => {
      assert.equal(authorization, bearer);
      assert.equal(user.actor_type, 'user');
      state.checks++;
      if (state.hook) await state.hook(state.checks);
    },
    publicationSource: { actor: async userId => ({ enabled: true, linked: true,
      requestRevision: userId === actorId ? 'b'.repeat(64) : null,
      reviewRevision: userId === reviewerId ? 'c'.repeat(64) : null }) },
  });
}
const create = (changes = {}) => store.blueprint({ name: 'Owned blueprint', platform: 'windows', ...confirmation, ...changes }, actor(), bearer);
const values = (rows, platform = 'windows') => ({ platform, blueprints: rows.map(row => ({ id: row.id, version: row.version })) });
const preview = (rows, platform = 'windows', user = actor(['policy-reader']), signal) => store.previewBlueprints(values(rows, platform), user, bearer, signal);
async function add(row, payload, configType = 'wifi') {
  return store.child('blueprint', row.id, etag('blueprint', row), {
    config_type: configType, config_name: 'Owned configuration', payload, ...confirmation,
  }, actor(), bearer, 'configuration_added');
}
async function addExact(row, payloadJson, configType = 'wifi') {
  const user = actor();
  return store.transaction(user, bearer, 'policies.manage', undefined, async client => {
    const parent = await store.lock(client, 'blueprint', row.id, etag('blueprint', row), user, bearer, 'policies.manage');
    await store.proof(client, context(user, 'policies.manage', 'blueprint', row.id, parent.version, 'configuration_added', confirmation.reason));
    const saved = (await client.query('INSERT INTO blueprint_configurations(blueprint_id,config_type,config_name,payload) VALUES($1,$2,$3,$4::jsonb) RETURNING *',
      [row.id, configType, 'Exact guarded PostgreSQL JSONB', payloadJson])).rows[0];
    return { row: saved, parent: (await client.query('SELECT * FROM blueprints WHERE id=$1', [row.id])).rows[0] };
  }, { write: true });
}
async function persisted(connectionPool = pool) {
  const result = {};
  for (const table of tables) result[table] = (await connectionPool.query(`SELECT COALESCE(jsonb_agg(to_jsonb(source) ORDER BY to_jsonb(source)::text),'[]'::jsonb) AS rows FROM ${table} source`)).rows[0].rows;
  return result;
}
async function legacy(seed, operation) {
  const legacySchema = 'blueprint_legacy_' + randomUUID().replaceAll('-', '');
  await administration.query(`CREATE SCHEMA ${legacySchema}`);
  const url = new URL(process.env.LICENSE_TEST_DATABASE_URL);
  url.searchParams.set('options', `-c search_path=${legacySchema},public`);
  const legacyPool = new Pool({ connectionString: url.toString(), max: 3 });
  try {
    for (const file of migrations.slice(0, 2)) await legacyPool.query(fs.readFileSync(path.join(__dirname, '../db/migrations', file), 'utf8'));
    const seeded = await seed(legacyPool);
    for (const file of migrations.slice(2)) await legacyPool.query(fs.readFileSync(path.join(__dirname, '../db/migrations', file), 'utf8'));
    await operation(makeStore(legacyPool), legacyPool, seeded);
  } finally {
    await legacyPool.end();
    await administration.query(`DROP SCHEMA IF EXISTS ${legacySchema} CASCADE`);
  }
}
async function approve(row) {
  const frame = await store.publications.get('blueprint', row.id, actor(), bearer);
  const requested = await store.publications.request('blueprint', row.id, etag('blueprint', row), {
    reviewerUserId: reviewerId, validitySeconds: 300, configurationHash: frame.configurationHash, ...confirmation,
  }, actor(), bearer);
  return store.publications.transition('blueprint', row.id, requested.id, publicationTag(requested), {
    decision: 'approved', resourceVersion: row.version, configurationHash: frame.configurationHash, ...confirmation,
  }, actor(['policy-publication-reviewer'], reviewerId), bearer);
}
async function delivery(row, configurationId) {
  const assigned = await store.child('blueprint', row.id, etag('blueprint', row), {
    target_type: 'device', target_id: 'owned-preview-device', ...confirmation,
  }, actor(), bearer, 'assigned');
  const publication = await approve(assigned.parent);
  return { reference: { resourceKind: 'blueprint', resourceId: row.id, resourceVersion: assigned.parent.version,
    publicationId: publication.id, configurationId }, deviceId: 'owned-preview-device', platform: 'windows', operationId: randomUUID() };
}

before(async () => {
  await administration.query(`CREATE SCHEMA ${schema}`);
  const url = new URL(process.env.LICENSE_TEST_DATABASE_URL);
  url.searchParams.set('options', `-c search_path=${schema},public`);
  pool = new Pool({ connectionString: url.toString(), max: 8 });
  for (const file of migrations) await pool.query(fs.readFileSync(path.join(__dirname, '../db/migrations', file), 'utf8'));
});
beforeEach(async () => {
  await pool.query('TRUNCATE ' + tables.join(',') + ' CASCADE');
  state = { checks: 0, hook: null };
  store = makeStore(pool);
});
after(async () => {
  if (pool) await pool.end();
  await administration.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
  await administration.end();
});

test('actual persisted selections retain input order and expose only the exact bounded preview contract', async () => {
  const first = await create({ name: 'First', platform: 'all' });
  const second = await create({ name: 'Second' });
  const unrelated = await add(await create(), { ssid: 'Unselected network' });
  const before = await persisted();
  const result = await preview([second, first]);
  assert.deepEqual(result, { schemaVersion: 1, scope: 'selected-blueprint-versions', comparison: 'whole-config-type', platform: 'windows',
    previewOnly: true, enforcementConfirmed: false, licenseReservations: 0,
    blueprints: [second, first].map(row => ({ id: row.id, name: row.name, platform: row.platform, version: row.version })),
    configurationCount: 0, hasConflicts: false, effectiveConfigurations: [], conflicts: [] });
  assert.equal(JSON.stringify(result).includes(unrelated.row.id), false);
  assert.deepEqual(await persisted(), before);
});

test('PostgreSQL object equality collapses reordered nested keys and preserves every actual source', async () => {
  const first = await addExact(await create(), '{"ssid":"Owned","security":{"mode":"wpa3","enabled":true}}');
  const second = await addExact(await create(), '{"security":{"enabled":true,"mode":"wpa3"},"ssid":"Owned"}');
  const result = await preview([first.parent, second.parent]);
  const actual = (await pool.query('SELECT payload::text AS payload_json FROM blueprint_configurations WHERE id=$1', [first.row.id])).rows[0].payload_json;
  assert.equal(result.configurationCount, 2);
  assert.equal(result.hasConflicts, false);
  assert.equal(result.effectiveConfigurations.length, 1);
  assert.equal(result.effectiveConfigurations[0].payloadJson, actual);
  assert.deepEqual(result.effectiveConfigurations[0].sources.map(source => source.configurationId).sort(), [first.row.id, second.row.id].sort());
  assert.deepEqual(Object.keys(result.effectiveConfigurations[0]).sort(), ['configType', 'payloadJson', 'sources']);
});

test('array ordering remains meaningful and conflicting types never enter effective configurations', async () => {
  const first = await add(await create(), { networks: ['first', 'second'] });
  const second = await add(await create(), { networks: ['second', 'first'] });
  const result = await preview([first.parent, second.parent]);
  assert.equal(result.hasConflicts, true);
  assert.deepEqual(result.effectiveConfigurations, []);
  assert.equal(result.conflicts[0].configType, 'wifi');
  assert.equal(result.conflicts[0].variants.length, 2);
  assert.deepEqual(result.conflicts[0].variants.map(item => JSON.parse(item.payloadJson).networks).sort(), [['first', 'second'], ['second', 'first']].sort());
});

test('whole-type comparison does not silently merge disjoint objects or impose a blueprint priority', async () => {
  const first = await add(await create(), { ssid: 'Owned' });
  const second = await add(await create(), { encryption: true });
  const unrelated = await add(second.parent, { minutes: 5 }, 'screen_lock');
  const forward = await preview([first.parent, unrelated.parent]);
  const reverse = await preview([unrelated.parent, first.parent]);
  assert.equal(forward.conflicts.length, 1);
  assert.equal(forward.conflicts[0].variants.length, 2);
  assert.equal(forward.effectiveConfigurations[0].configType, 'screen_lock');
  assert.deepEqual(forward.conflicts, reverse.conflicts);
  assert.deepEqual(forward.effectiveConfigurations, reverse.effectiveConfigurations);
});

test('one blueprint can itself contain a conflict while equal duplicate sources do not become extra variants', async () => {
  const first = await add(await create(), { ssid: 'First' });
  const duplicate = await add(first.parent, { ssid: 'First' });
  const second = await add(duplicate.parent, { ssid: 'Second' });
  const result = await preview([second.parent]);
  assert.equal(result.configurationCount, 3);
  assert.equal(result.conflicts[0].variants.length, 2);
  assert.deepEqual(result.conflicts[0].variants.map(item => item.sources.length).sort(), [1, 2]);
});

test('exact JSONB integers beyond JavaScript precision remain separate conflict variants and exact payload strings', async () => {
  const first = await addExact(await create(), '{"identifier":9007199254740992}');
  const second = await addExact(await create(), '{"identifier":9007199254740993}');
  const result = await preview([first.parent, second.parent]);
  assert.equal(result.hasConflicts, true);
  assert.deepEqual(result.conflicts[0].variants.map(item => item.payloadJson).sort(), ['{"identifier": 9007199254740992}', '{"identifier": 9007199254740993}']);
});

test('PostgreSQL numeric equality treats one and one-point-zero as the same payload without JavaScript grouping', async () => {
  const first = await addExact(await create(), '{"version":1}');
  const second = await addExact(await create(), '{"version":1.0}');
  const result = await preview([first.parent, second.parent]);
  assert.equal(result.hasConflicts, false);
  assert.equal(result.effectiveConfigurations[0].sources.length, 2);
  const stored = (await pool.query('SELECT payload::text AS payload_json FROM blueprint_configurations')).rows.map(row => row.payload_json);
  assert.ok(stored.includes(result.effectiveConfigurations[0].payloadJson));
});

for (const platform of ['windows', 'macos', 'linux']) {
  test('all-platform and concrete persisted blueprints can be previewed for ' + platform, async () => {
    const common = await create({ platform: 'all' });
    const concrete = await create({ platform });
    assert.equal((await preview([common, concrete], platform)).platform, platform);
  });
}

test('incompatible platforms fail rather than dropping the mismatched selected blueprint', async () => {
  const row = await create({ platform: 'macos' });
  await assert.rejects(preview([row]), { status: 409, code: 'blueprint_platform_mismatch' });
});

test('a captured version made stale by an actual child transition cannot preview the replacement content', async () => {
  const row = await create();
  const changed = await add(row, { ssid: 'New version' });
  await assert.rejects(preview([row]), { status: 412, code: 'policy_configuration_changed' });
  assert.equal((await preview([changed.parent])).configurationCount, 1);
});

test('actual deleted and unknown UUIDs return not found instead of a partial successful selection', async () => {
  const row = await create();
  await store.blueprint(confirmation, actor(), bearer, undefined, row.id, etag('blueprint', row), 'deleted');
  const existing = await create();
  for (const missing of [row, { id: randomUUID(), version: 1 }]) await assert.rejects(preview([existing, missing]), { status: 404, code: 'policy_resource_not_found' });
});

test('a withdrawn original bearer is checked before any successful preview', async () => {
  const row = await create();
  const before = await persisted();
  state.checks = 0;
  state.hook = async () => { throw Object.assign(new Error('Owned bearer withdrawn'), { status: 401, code: 'owned_bearer_withdrawn' }); };
  await assert.rejects(preview([row]), { status: 401 });
  assert.equal(state.checks, 1);
  assert.deepEqual(await persisted(), before);
});

test('mandatory live authority recheck after source reads rejects withdrawal without saving effects', async () => {
  const row = await add(await create(), { ssid: 'Owned' });
  const before = await persisted();
  state.checks = 0;
  state.hook = async count => { if (count === 2) throw Object.assign(new Error('Owned source withdrawn after read'), { status: 401 }); };
  await assert.rejects(preview([row.parent]), { status: 401 });
  assert.equal(state.checks, 2);
  assert.deepEqual(await persisted(), before);
});

for (const kind of ['ordinary-user', 'service-actor', 'injected-scope']) {
  test('preview cannot manufacture canonical policy authority from ' + kind, async () => {
    const row = await create();
    const user = actor(kind === 'service-actor' ? ['admin'] : ['user']);
    if (kind === 'service-actor') user.actor_type = 'application';
    if (kind === 'injected-scope') { user.scope = 'policies.preview'; user.permissions = ['policies.preview']; }
    state.checks = 0;
    await assert.rejects(preview([row], 'windows', user), { status: 403, code: 'policy_operation_forbidden' });
    assert.equal(state.checks, 0);
  });
}

test('a canonical reader can preview without acquiring write MFA or publication duties', async () => {
  const row = await create();
  const user = actor(['policy-reader']);
  delete user.auth_time;
  delete user.amr;
  delete user.mfa_authorization;
  assert.equal((await preview([row], 'windows', user)).previewOnly, true);
  await assert.rejects(store.blueprint({ name: 'Forbidden', ...confirmation }, user, bearer), { status: 403 });
});

test('an already aborted operation cannot open a source transaction', async () => {
  const row = await create();
  const controller = new AbortController();
  controller.abort();
  state.checks = 0;
  await assert.rejects(preview([row], 'windows', actor(['policy-reader']), controller.signal), { status: 409, code: 'policy_operation_closed' });
  assert.equal(state.checks, 0);
});

test('an abort during the final authority check rolls back instead of returning a successful preview', async () => {
  const row = await create();
  const before = await persisted();
  const controller = new AbortController();
  state.checks = 0;
  state.hook = async count => { if (count === 2) controller.abort(); };
  await assert.rejects(preview([row], 'windows', actor(['policy-reader']), controller.signal), { status: 409, code: 'policy_operation_closed' });
  assert.deepEqual(await persisted(), before);
});

test('the actual PostgreSQL transaction is repeatable-read and read-only and leaves all source and evidence rows byte-equivalent', async () => {
  const configured = await add(await create(), { ssid: 'Owned' });
  const before = await persisted();
  const originalConnect = store.database.getClient;
  const settings = [];
  store.database.getClient = async () => {
    const client = await originalConnect();
    return { release: () => client.release(), query: async (...args) => {
      const result = await client.query(...args);
      if (args[0].startsWith('SELECT id,name,platform,version')) settings.push((await client.query("SELECT current_setting('transaction_isolation') AS isolation,current_setting('transaction_read_only') AS readonly")).rows[0]);
      return result;
    } };
  };
  await preview([configured.parent]);
  assert.deepEqual(settings, [{ isolation: 'repeatable read', readonly: 'on' }]);
  assert.deepEqual(await persisted(), before);
});

test('a writer committed between parent and child reads cannot mix a newer child generation into the captured repeatable-read snapshot', async () => {
  const first = await add(await create(), { ssid: 'Captured' });
  let observed;
  let resume;
  const parentRead = new Promise(resolve => { observed = resolve; });
  const writerCommitted = new Promise(resolve => { resume = resolve; });
  const reader = makeStore(pool);
  const originalConnect = reader.database.getClient;
  reader.database.getClient = async () => {
    const client = await originalConnect();
    return { release: () => client.release(), query: async (...args) => {
      const result = await client.query(...args);
      if (args[0].startsWith('SELECT id,name,platform,version')) { observed(); await writerCommitted; }
      return result;
    } };
  };
  const pending = reader.previewBlueprints(values([first.parent]), actor(['policy-reader']), bearer);
  try {
    await parentRead;
    const second = await add(first.parent, { ssid: 'Concurrent replacement' });
    resume();
    const result = await pending;
    assert.equal(result.blueprints[0].version, first.parent.version);
    assert.equal(result.configurationCount, 1);
    assert.equal(result.hasConflicts, false);
    assert.equal((await preview([second.parent])).hasConflicts, true);
    await assert.rejects(preview([first.parent]), { status: 412 });
  } finally { resume(); await pending.catch(() => {}); }
});

for (const count of [1000, 1001]) {
  test('the aggregate persisted configuration bound is enforced across selected blueprints at ' + count + ' rows', async () => {
    await legacy(async connectionPool => {
      const first = randomUUID();
      const second = randomUUID();
      await connectionPool.query("INSERT INTO blueprints(id,name,platform) VALUES($1,'First legacy source','windows'),($2,'Second legacy source','windows')", [first, second]);
      await connectionPool.query("INSERT INTO blueprint_configurations(blueprint_id,config_type,config_name,payload) SELECT CASE WHEN generated<=500 THEN $1::uuid ELSE $2::uuid END,'wifi','Observed legacy configuration','{}'::jsonb FROM generate_series(1,$3::int) generated", [first, second, count]);
      return [{ id: first, version: 1 }, { id: second, version: 1 }];
    }, async (legacyStore, connectionPool, selected) => {
      const before = await persisted(connectionPool);
      const pending = legacyStore.previewBlueprints(values(selected), actor(['policy-reader']), bearer);
      if (count === 1000) assert.equal((await pending).configurationCount, count);
      else await assert.rejects(pending, { status: 409, code: 'blueprint_preview_limit_reached' });
      assert.deepEqual(await persisted(connectionPool), before);
    });
  });
}

test('exactly one MiB of actual JSONB text is permitted and additional UTF-8 bytes are not silently truncated', async () => {
  let row = await create();
  for (let index = 0; index < 4; index++) row = (await add(row, { text: 'x'.repeat(250000) })).parent;
  const measured = (await pool.query('SELECT sum(octet_length(payload::text))::int AS bytes FROM blueprint_configurations WHERE blueprint_id=$1', [row.id])).rows[0].bytes;
  row = (await add(row, { text: 'x'.repeat(1048576 - measured - 12) })).parent;
  assert.equal((await pool.query('SELECT sum(octet_length(payload::text))::int AS bytes FROM blueprint_configurations WHERE blueprint_id=$1', [row.id])).rows[0].bytes, 1048576);
  assert.equal((await preview([row])).configurationCount, 5);
  row = (await add(row, { text: 'é' })).parent;
  const before = await persisted();
  await assert.rejects(preview([row]), { status: 409, code: 'blueprint_preview_limit_reached' });
  assert.deepEqual(await persisted(), before);
});

for (const payloadJson of ['[]', 'null', '{"nested":{"constructor":"unsafe"}}']) {
  test('invalid observed legacy payload fails closed without disabling guards: ' + payloadJson, async () => {
    await legacy(async connectionPool => {
      const row = (await connectionPool.query("INSERT INTO blueprints(name,platform) VALUES('Observed corrupt payload','windows') RETURNING id")).rows[0];
      await connectionPool.query("INSERT INTO blueprint_configurations(blueprint_id,config_type,config_name,payload) VALUES($1,'wifi','Observed payload',$2::jsonb)", [row.id, payloadJson]);
      return { ...row, version: 1 };
    }, async (legacyStore, connectionPool, row) => {
      const before = await persisted(connectionPool);
      await assert.rejects(legacyStore.previewBlueprints(values([row]), actor(['policy-reader']), bearer), { status: 503, code: 'blueprint_preview_source_unavailable' });
      assert.deepEqual(await persisted(connectionPool), before);
    });
  });
}

test('invalid observed legacy platform is an unavailable source rather than a fabricated compatible preview', async () => {
  await legacy(async connectionPool => ({ ...(await connectionPool.query("INSERT INTO blueprints(name,platform) VALUES('Observed invalid platform','unsupported') RETURNING id")).rows[0], version: 1 }),
    async (legacyStore, connectionPool, row) => {
      const before = await persisted(connectionPool);
      await assert.rejects(legacyStore.previewBlueprints(values([row]), actor(['policy-reader']), bearer), { status: 503, code: 'blueprint_preview_source_unavailable' });
      assert.deepEqual(await persisted(connectionPool), before);
    });
});

test('an unavailable required configuration table cannot produce a partial successful preview', async () => {
  const row = await create();
  await pool.query('ALTER TABLE blueprint_configurations RENAME TO owned_preview_missing_source');
  try { await assert.rejects(preview([row]), { status: 503, code: 'policy_configuration_unavailable' }); }
  finally { await pool.query('ALTER TABLE owned_preview_missing_source RENAME TO blueprint_configurations'); }
});

test('an actually independently approved conflicting blueprint is rejected by direct delivery-frame admission without extra evidence', async () => {
  const first = await add(await create(), { ssid: 'First' });
  const second = await add(first.parent, { ssid: 'Second' });
  const request = await delivery(second.parent, first.row.id);
  const before = await persisted();
  await assert.rejects(store.publications.deliveryFrame(request, actor(), bearer), { status: 409, code: 'blueprint_configuration_conflict' });
  assert.deepEqual(await persisted(), before);
});

test('an actually approved nonconflicting unsafe JSONB integer is not rounded into a successful delivery frame', async () => {
  const exact = await addExact(await create(), '{"identifier":9007199254740993}');
  const request = await delivery(exact.parent, exact.row.id);
  const before = await persisted();
  assert.equal((await preview([{ id: request.reference.resourceId, version: request.reference.resourceVersion }])).hasConflicts, false);
  await assert.rejects(store.publications.deliveryFrame(request, actor(), bearer), { status: 503, code: 'blueprint_payload_not_lossless' });
  assert.deepEqual(await persisted(), before);
});

test('nonconflicting exact numeric equality still permits an actual approved lossless delivery frame', async () => {
  const first = await addExact(await create(), '{"version":1}');
  const second = await addExact(first.parent, '{"version":1.0}');
  const request = await delivery(second.parent, second.row.id);
  const before = await persisted();
  const result = await store.publications.deliveryFrame(request, actor(), bearer);
  assert.deepEqual(result.payload.settings, { version: 1 });
  assert.equal(result.reference.configurationId, second.row.id);
  assert.deepEqual(await persisted(), before);
});
