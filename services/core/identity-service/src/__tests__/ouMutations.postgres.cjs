'use strict';

const { test, before, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const fs = require('node:fs'); const path = require('node:path'); const { Pool } = require('pg');
const { OuMutator, ouEtag } = require('../OuMutator');
const { DirectoryCreator } = require('../DirectoryCreator'); const { DirectoryReader } = require('../DirectoryReader'); const { AuthorizationState } = require('../AuthorizationState');
const { sameContext } = require('../../../../../packages/identity-authorization-contract');
const { provisionTenant, adoptTenant } = require('../../../../../scripts/lib/tenant-ownership-fixture.cjs');
const schema = 'ou_mutations_' + randomUUID().replaceAll('-', ''); const issuer = 'https://ou-mutations.test'; const migrations = path.join(__dirname, '../../migrations');
const administration = new Pool({ connectionString: process.env.IDENTITY_TEST_DATABASE_URL, max: 1 }); let pool; let database; let beforeCommit;
before(async () => {
  await administration.query('CREATE SCHEMA ' + schema); pool = new Pool({ connectionString: process.env.IDENTITY_TEST_DATABASE_URL, max: 10, options: `-c search_path=${schema},public` });
  database = { isAvailable: () => true, query: (...args) => pool.query(...args), getClient: () => pool.connect(), transaction: async (operation, options = {}) => {
    const client = await pool.connect();
    try { await client.query(options.readOnly ? 'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY' : 'BEGIN'); await client.query("SET LOCAL lock_timeout='5s';SET LOCAL statement_timeout='15s'");
      if (options.actor) await client.query("SELECT set_config('opendirectory.actor',$1,true)", [options.actor]); const result = await operation(client); if (!options.readOnly && beforeCommit) await beforeCommit(client); await client.query('COMMIT'); return result;
    } catch (error) { await client.query('ROLLBACK'); throw error; } finally { client.release(); }
  } };
  for (const file of fs.readdirSync(migrations).filter(file => file.endsWith('.sql')).sort()) await pool.query(fs.readFileSync(path.join(migrations, file), 'utf8'));
});
beforeEach(async () => { beforeCommit = null; await pool.query('TRUNCATE identity_tenants,users,groups,ous CASCADE'); });
after(async () => { await pool.end(); await administration.query('DROP SCHEMA ' + schema + ' CASCADE'); await administration.end(); });
async function actor(role = 'ou-administrator', tenant) {
  tenant ||= await provisionTenant(database, schema, { enabled: true }); const id = randomUUID(); const subject = 'ou-operator-' + id;
  await pool.query('INSERT INTO users(id,username,email) VALUES($1,$2,$3)', [id, subject, id + '@example.invalid']); await pool.query('INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES($1,$2,$3)', [issuer, subject, id]);
  await adoptTenant(database, schema, tenant, [{ kind: 'user', resourceId: id }]); await pool.query('INSERT INTO identity_role_assignments(user_id,role,reason) VALUES($1,$2,$3)', [id, role, 'Explicit own-tenant OU operator']);
  const state = await new AuthorizationState(database).state(issuer, subject); const authTime = Math.floor(Date.now() / 1000);
  const user = { iss: issuer, sub: subject, actor_type: 'user', roles: state.roles, identity_authorization: state.context, exp: authTime + 300, auth_time: authTime, amr: ['pwd', 'otp'], mfa_authorization: { schemaVersion: 1, userId: id, revision: '1', authTime, methods: ['pwd', 'otp'] } };
  const live = { checks: 0, revoked: false, onCheck: null }; const revalidate = async (_authorization, original) => {
    live.checks++; if (live.onCheck) await live.onCheck(live.checks); const current = await new AuthorizationState(database).state(issuer, original.sub);
    if (live.revoked || !current.active || !sameContext(current.context, original.identity_authorization)) throw Object.assign(new Error('Original OU bearer rejected'), { status: 401 }); return current.tenant;
  };
  const options = { issuer, revalidate }; return { tenant, id, user, live, options, creator: new DirectoryCreator(database, options), reader: new DirectoryReader(database, options), mutator: new OuMutator(database, options) };
}
const create = (fixture, name = 'Owned unit', parentId = null) => fixture.creator.ou({ name, parentId }, fixture.user, 'Bearer original');
const read = (fixture, id) => fixture.reader.ou(id, {}, fixture.user, 'Bearer original');
const update = (fixture, unit, changes = { description: 'Actual own change' }) => fixture.mutator.update(unit.id, changes, ouEtag(unit), fixture.user, 'Bearer original');
const remove = (fixture, unit) => fixture.mutator.remove(unit.id, ouEtag(unit), fixture.user, 'Bearer original');
const events = async () => (await pool.query('SELECT event.*,outbox.status FROM identity_directory_ou_events event JOIN identity_directory_ou_outbox outbox USING(id) ORDER BY event.created_at')).rows;
function wrapped(operation) { return { ...database, transaction: (callback, options) => database.transaction(async client => { const result = await callback(client); await operation(client); return result; }, options) }; }
test('own OU metadata changes retain exact revisions, original human proof, before/after event and pending outbox', async () => {
  const fixture = await actor(); const unit = await create(fixture); const changed = await update(fixture, unit); assert.equal(changed.description, 'Actual own change'); assert.equal(BigInt(changed.revision), BigInt(unit.revision) + 1n); assert.deepEqual(await read(fixture, unit.id), changed);
  const [event] = await events(); assert.equal(event.tenant_id, fixture.tenant); assert.equal(event.type, 'organization-unit.updated'); assert.equal(event.version, 1); assert.equal(event.correlation_id, event.id); assert.equal(event.actor.userId, fixture.id); assert.equal(event.before_state.revision, unit.revision); assert.equal(event.after_state.revision, changed.revision); assert.equal(event.status, 'pending'); assert.equal(JSON.stringify(event).includes('Bearer'), false);
});
test('a subtree can move between own roots without losing descendants or mutating an unrelated unit', async () => {
  const fixture = await actor(); const root = await create(fixture, 'Root'); const other = await create(fixture, 'Other root'); const child = await create(fixture, 'Child', root.id); const grandchild = await create(fixture, 'Grandchild', child.id);
  const moved = await update(fixture, child, { parentId: other.id }); assert.equal(moved.parentId, other.id); assert.equal((await read(fixture, grandchild.id)).parentId, child.id); assert.equal((await read(fixture, root.id)).revision, root.revision); assert.equal((await events()).length, 1);
});
test('deleting a non-leaf is rejected while a leaf retirement retains exact negative ownership and immutable event evidence', async () => {
  const fixture = await actor(); const root = await create(fixture); const child = await create(fixture, 'Child', root.id); await assert.rejects(remove(fixture, root), error => error.status === 409); assert.equal((await events()).length, 0);
  await remove(fixture, child); await assert.rejects(read(fixture, child.id), error => error.status === 404); assert.equal((await read(fixture, root.id)).revision, root.revision);
  const [event] = await events(); assert.equal(event.type, 'organization-unit.deleted'); assert.equal(event.after_state, null); assert.equal((await pool.query("SELECT count(*)::int AS count FROM identity_tenant_retirements WHERE resource_kind='ou' AND resource_id=$1 AND tenant_id=$2", [child.id, fixture.tenant])).rows[0].count, 1);
});
test('a global role does not permit foreign OU metadata, retirement or parent assignment', async () => {
  const fixture = await actor('admin'); const foreign = await actor(); const own = await create(fixture); const other = await create(foreign);
  await assert.rejects(update(fixture, other), error => error.status === 404); await assert.rejects(remove(fixture, other), error => error.status === 404); await assert.rejects(update(fixture, own, { parentId: other.id }), error => error.status === 404); assert.equal((await events()).length, 0); assert.deepEqual(await read(foreign, other.id), other);
});
test('a normal reader cannot borrow an owned namespace to change or delete a unit', async () => {
  const owner = await actor(); const unit = await create(owner); const reader = await actor('directory-reader', owner.tenant); await assert.rejects(update(reader, unit), error => error.status === 403); await assert.rejects(remove(reader, unit), error => error.status === 403); assert.equal((await events()).length, 0);
});
test('missing, weak, mismatched and stale preconditions do not commit a mutation', async () => {
  const fixture = await actor(); const unit = await create(fixture);
  for (const [etag, status] of [[undefined, 428], ['*', 400], ['W/' + ouEtag(unit), 400], [ouEtag({ ...unit, id: randomUUID() }), 412]]) await assert.rejects(fixture.mutator.update(unit.id, { name: 'Rejected' }, etag, fixture.user, 'Bearer original'), error => error.status === status);
  const changed = await update(fixture, unit); await assert.rejects(update(fixture, unit), error => error.status === 412); assert.deepEqual(await read(fixture, unit.id), changed); assert.equal((await events()).length, 1);
});
test('self-parent and descendant-parent changes cannot create cycles', async () => {
  const fixture = await actor(); const root = await create(fixture); const child = await create(fixture, 'Child', root.id);
  for (const parentId of [root.id, child.id]) await assert.rejects(update(fixture, root, { parentId }), error => error.status === 409); assert.equal((await events()).length, 0);
});
test('subtree moves enforce the actual deepest descendant at the 256-level boundary', async () => {
  const fixture = await actor(); const units = Array.from({ length: 257 }, (_, index) => ({ id: randomUUID(), name: 'Existing unit ' + index }));
  await pool.query("INSERT INTO ous(id,name) SELECT (unit->>'id')::uuid,unit->>'name' FROM jsonb_array_elements($1::jsonb) unit", [JSON.stringify(units)]); await adoptTenant(database, schema, fixture.tenant, units.map(unit => ({ kind: 'ou', resourceId: unit.id })));
  const links = units.slice(1, 255).map((unit, index) => ({ id: unit.id, parent: units[index].id })); links.push({ id: units[256].id, parent: units[255].id });
  await pool.query("UPDATE ous SET parent_id=(link->>'parent')::uuid FROM jsonb_array_elements($1::jsonb) link WHERE ous.id=(link->>'id')::uuid", [JSON.stringify(links)]);
  const subtree = await read(fixture, units[255].id); await assert.rejects(update(fixture, subtree, { parentId: units[254].id }), error => error.status === 409); assert.equal((await events()).length, 0);
  const changed = await update(fixture, subtree, { parentId: units[253].id }); assert.equal(changed.parentId, units[253].id); assert.equal((await fixture.reader.ous({}, fixture.user, 'Bearer original')).total, 257);
});
test('late original bearer withdrawal rolls the actual OU effect and both new evidence rows back', async () => {
  const fixture = await actor(); const unit = await create(fixture); fixture.live.checks = 0; fixture.live.onCheck = async count => { if (count === 3) fixture.live.revoked = true; };
  await assert.rejects(update(fixture, unit), error => error.status === 401); fixture.live.revoked = false; fixture.live.onCheck = null; assert.deepEqual(await read(fixture, unit.id), unit); assert.equal((await events()).length, 0);
});
test('physical original proof expiry at SQL commit rolls the confirmed in-transaction effect back', { timeout: 15000 }, async () => {
  const fixture = await actor(); const unit = await create(fixture); fixture.user.exp = Math.floor(Date.now() / 1000) + 2; beforeCommit = async () => { await new Promise(resolve => setTimeout(resolve, 2200)); };
  await assert.rejects(update(fixture, unit), error => ['42501', '28000'].includes(error.code)); beforeCommit = null; assert.equal((await pool.query('SELECT description FROM ous WHERE id=$1', [unit.id])).rows[0].description, null); assert.equal((await events()).length, 0);
});
test('cleared scopes, unrelated writes and truncation cannot ride a retained OU command', async () => {
  const fixture = await actor(); const unit = await create(fixture);
  for (const sql of ["UPDATE users SET title='Unrelated'", 'TRUNCATE groups CASCADE', "UPDATE ous SET description='Second unrequested change'"]) {
    const mutator = new OuMutator(wrapped(async client => { await client.query("SELECT set_config('opendirectory.ou_mutation','',true)"); await client.query(sql); }), fixture.options);
    await assert.rejects(mutator.update(unit.id, { name: 'No commit' }, ouEtag(unit), fixture.user, 'Bearer original'), error => error.code === '42501'); assert.deepEqual(await read(fixture, unit.id), unit); assert.equal((await events()).length, 0);
  }
});
test('missing required receivers deny admission and removed commit guards roll an already received command back', async () => {
  const fixture = await actor(); const unit = await create(fixture); await pool.query('ALTER TABLE ous DISABLE TRIGGER zzz_identity_directory_ou_revision');
  try { await assert.rejects(update(fixture, unit), error => error.status === 503); } finally { await pool.query('ALTER TABLE ous ENABLE TRIGGER zzz_identity_directory_ou_revision'); }
  const mutator = new OuMutator(wrapped(client => client.query('ALTER TABLE groups DISABLE TRIGGER aaa_identity_directory_ou_fence')), fixture.options);
  await assert.rejects(mutator.update(unit.id, { name: 'Rejected receiver removal' }, ouEtag(unit), fixture.user, 'Bearer original'), error => error.code === '42501'); assert.equal((await events()).length, 0);
});
test('a suppressed event or outbox cannot turn a partial OU transition into a positive receipt', async () => {
  const fixture = await actor(); const unit = await create(fixture);
  for (const table of ['identity_directory_ou_events', 'identity_directory_ou_outbox']) {
    await pool.query('CREATE FUNCTION omit_ou_evidence() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL;END; $$;CREATE TRIGGER zzzz_omit_ou_evidence BEFORE INSERT ON ' + table + ' FOR EACH ROW EXECUTE FUNCTION omit_ou_evidence()');
    try { await assert.rejects(update(fixture, unit), error => error.status === 503 || error.code === '23514'); } finally { await pool.query('DROP TRIGGER zzzz_omit_ou_evidence ON ' + table + ';DROP FUNCTION omit_ou_evidence()'); }
    assert.deepEqual(await read(fixture, unit.id), unit); assert.equal((await events()).length, 0);
  }
});
test('late row-trigger content drift is rejected at the final actual-state fence', async () => {
  const fixture = await actor(); const unit = await create(fixture); await pool.query("CREATE FUNCTION drift_ou() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN NEW.description='Not requested';RETURN NEW;END; $$;CREATE TRIGGER zzzz_drift_ou BEFORE UPDATE ON ous FOR EACH ROW EXECUTE FUNCTION drift_ou()");
  try { await assert.rejects(update(fixture, unit), error => error.code === '23514'); } finally { await pool.query('DROP TRIGGER zzzz_drift_ou ON ous;DROP FUNCTION drift_ou()'); }
  assert.deepEqual(await read(fixture, unit.id), unit); assert.equal((await events()).length, 0);
});
test('migration replay and caller timezones retain exact revisions and immutable command evidence', async () => {
  const fixture = await actor(); const unit = await create(fixture); const changed = await update(fixture, unit); const evidence = await events();
  await pool.query(fs.readFileSync(path.join(migrations, '042_directory_ou_mutations.sql'), 'utf8')); await pool.query("SET timezone='Pacific/Honolulu'"); assert.deepEqual(await read(fixture, unit.id), changed); assert.deepEqual(await events(), evidence);
  for (const file of fs.readdirSync(migrations).filter(file => file.endsWith('.sql') && file > '042_directory_ou_mutations.sql').sort()) await pool.query(fs.readFileSync(path.join(migrations, file), 'utf8'));
  for (const sql of ['DELETE FROM identity_directory_ou_events', "UPDATE identity_directory_ou_outbox SET status='pending'"]) await assert.rejects(pool.query(sql), error => error.code === '42501');
});
async function observedTreeWait() {
  const until = Date.now() + 2000;
  while (Date.now() < until) { if ((await pool.query("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query='SELECT identity_directory_ou_lock($1)') AS waiting")).rows[0].waiting) return; await new Promise(resolve => setTimeout(resolve, 10)); }
  assert.fail('Expected actual OU advisory-lock wait');
}
function holdNextCommit() {
  let readySignal; let release; let held = true; const ready = new Promise(resolve => { readySignal = resolve; }); const gate = new Promise(resolve => { release = resolve; });
  beforeCommit = async () => { if (held) { held = false; readySignal(); await gate; } }; return { ready, release: () => { release(); } };
}
test('actual competing updates wait on the tree boundary and a stale second writer cannot overwrite the first version', { timeout: 15000 }, async () => {
  const fixture = await actor(); const unit = await create(fixture); const gate = holdNextCommit(); const first = update(fixture, unit, { name: 'First exact version' }); await gate.ready;
  const second = assert.rejects(update(fixture, unit, { name: 'Stale second version' }), error => error.status === 412);
  try { await observedTreeWait(); } finally { gate.release(); } await first; await second; beforeCommit = null; assert.equal((await read(fixture, unit.id)).name, 'First exact version'); assert.equal((await events()).length, 1);
});
test('actual opposite subtree moves serialize and cannot jointly commit an otherwise individually plausible cycle', { timeout: 15000 }, async () => {
  const fixture = await actor(); const firstRoot = await create(fixture, 'First'); const secondRoot = await create(fixture, 'Second'); const gate = holdNextCommit(); const first = update(fixture, firstRoot, { parentId: secondRoot.id }); await gate.ready;
  const second = assert.rejects(update(fixture, secondRoot, { parentId: firstRoot.id }), error => error.status === 409);
  try { await observedTreeWait(); } finally { gate.release(); } await first; await second; beforeCommit = null; assert.equal((await read(fixture, firstRoot.id)).parentId, secondRoot.id); assert.equal((await read(fixture, secondRoot.id)).parentId, undefined); assert.equal((await events()).length, 1);
});
test('a child creation racing parent deletion commits the child before the waiting deletion rechecks its actual dependencies', { timeout: 15000 }, async () => {
  const fixture = await actor(); const parent = await create(fixture); const gate = holdNextCommit(); const child = create(fixture, 'Concurrent child', parent.id); await gate.ready;
  const deleting = assert.rejects(remove(fixture, parent), error => error.status === 409);
  try { await observedTreeWait(); } finally { gate.release(); } const created = await child; await deleting; beforeCommit = null; assert.equal((await read(fixture, created.id)).parentId, parent.id); assert.equal((await events()).length, 0);
});
test('an actual limited SQL login or SET ROLE cannot launder the private OU mutation receiver', async () => {
  const role = 'ou_limited_' + randomUUID().replaceAll('-', ''); let limited;
  try {
    await administration.query('CREATE ROLE ' + role + ' LOGIN'); await pool.query('GRANT USAGE ON SCHEMA ' + schema + ' TO ' + role + ';GRANT EXECUTE ON FUNCTION identity_directory_ou_change(jsonb) TO ' + role);
    const address = new URL(process.env.IDENTITY_TEST_DATABASE_URL); address.username = role; limited = new Pool({ connectionString: address.toString(), options: `-c search_path=${schema},public`, max: 1 });
    for (const assumed of [false, true]) { const client = await (assumed ? pool : limited).connect();
      try { await client.query('BEGIN'); if (assumed) await client.query('SET LOCAL ROLE ' + role); await assert.rejects(client.query('SELECT identity_directory_ou_change($1::jsonb)', ['{}']), error => error.code === '42501' && error.message.includes('Actual database owner required')); }
      finally { await client.query('ROLLBACK'); client.release(); }
    }
  } finally { await limited?.end(); await pool.query('DROP OWNED BY ' + role); await administration.query('DROP ROLE ' + role); }
});
test('a retained original creation admission detects cleared proofs and rejects unrelated effects before physical commit', async () => {
  const fixture = await actor();
  for (const operation of [client => client.query("SELECT set_config('opendirectory.directory_creation','',true)"), client => client.query("UPDATE users SET title='Unrelated creation effect'")]) {
    const identity = randomUUID(); const creator = new DirectoryCreator(wrapped(operation), { ...fixture.options, newResourceId: () => identity });
    await assert.rejects(creator.ou({ name: 'No missing original creation proof' }, fixture.user, 'Bearer original'), error => error.code === '42501');
    assert.equal((await pool.query('SELECT count(*)::int AS count FROM ous WHERE id=$1', [identity])).rows[0].count, 0); assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_directory_ou_creations WHERE ou_id=$1', [identity])).rows[0].count, 0);
  }
});
test('a suppressed creation admission cannot silently fall back to bare unbound OU insertion', async () => {
  const fixture = await actor(); await pool.query('CREATE FUNCTION omit_ou_creation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL;END; $$;CREATE TRIGGER zzzz_omit_ou_creation BEFORE INSERT ON identity_directory_ou_creations FOR EACH ROW EXECUTE FUNCTION omit_ou_creation()');
  try { await assert.rejects(create(fixture), error => error.code === '23514'); } finally { await pool.query('DROP TRIGGER zzzz_omit_ou_creation ON identity_directory_ou_creations;DROP FUNCTION omit_ou_creation()'); }
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM ous')).rows[0].count, 0);
});
test('a second otherwise valid new-OU proof cannot ride an already received OU mutation in the same transaction', async () => {
  const fixture = await actor(); const unit = await create(fixture); const extraId = randomUUID();
  const mutator = new OuMutator(wrapped(async client => {
    const original = (await client.query('SELECT proof FROM identity_directory_ou_events WHERE transaction_id=txid_current()')).rows[0].proof;
    const proof = { issuer: original.issuer, subject: original.subject, context: original.context, tenant: original.tenant, rolesSnapshot: original.rolesSnapshot, validUntil: original.validUntil, resource: { kind: 'ou', id: extraId, values: { name: 'Unrequested second unit', description: null, parentId: null } } };
    await client.query("SELECT set_config('opendirectory.directory_creation',$1,true)", [JSON.stringify(proof)]); await client.query('SELECT identity_directory_ou_creation_admit($1::jsonb)', [JSON.stringify(proof)]);
    await client.query('INSERT INTO ous(id,name,description,parent_id) VALUES($1,$2,NULL,NULL)', [extraId, proof.resource.values.name]);
  }), fixture.options);
  await assert.rejects(mutator.update(unit.id, { name: 'No mixed command commit' }, ouEtag(unit), fixture.user, 'Bearer original'), error => error.code === '42501');
  assert.deepEqual(await read(fixture, unit.id), unit); assert.equal((await pool.query('SELECT count(*)::int AS count FROM ous')).rows[0].count, 1); assert.equal((await events()).length, 0);
});
