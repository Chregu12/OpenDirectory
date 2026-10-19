'use strict';

const { test, before, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const fs = require('node:fs'); const path = require('node:path'); const { Pool } = require('pg');
const { OuMutator, ouEtag } = require('../OuMutator');
const { DirectoryCreator } = require('../DirectoryCreator'); const { DirectoryReader } = require('../DirectoryReader'); const { AuthorizationState } = require('../AuthorizationState');
const { sameContext } = require('../../../../../packages/identity-authorization-contract');
const { provisionTenant, adoptTenant } = require('../../../../../scripts/lib/tenant-ownership-fixture.cjs');
const schema = 'ou_memberships_' + randomUUID().replaceAll('-', ''); const issuer = 'https://ou-mutations.test'; const migrations = path.join(__dirname, '../../migrations');
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

const create = (fixture, name = 'Own unit') => fixture.creator.ou({ name }, fixture.user, 'Bearer original');
const page = (fixture, unit, query = {}) => fixture.reader.ouMembers(unit.id, query, fixture.user, 'Bearer original');
const add = (fixture, unit, userId) => fixture.mutator.addMember(unit.id, { userId }, ouEtag(unit), fixture.user, 'Bearer original');
const unlink = (fixture, result) => fixture.mutator.removeMember(result.unit.id, result.membership.id, ouEtag(result.unit), fixture.user, 'Bearer original');
const read = (fixture, unit) => fixture.reader.ou(unit.id, {}, fixture.user, 'Bearer original');
const events = async () => (await pool.query('SELECT event.*,outbox.status FROM identity_directory_ou_events event JOIN identity_directory_ou_outbox outbox USING(id) ORDER BY event.created_at')).rows;
async function person(fixture, name = 'Employee') {
  const id = randomUUID(); await pool.query("INSERT INTO users(id,username,email,display_name,department,enabled) VALUES($1,$2,$3,$4,'Preserved external department',false)", [id, 'employee-' + id, id + '@example.invalid', name]);
  await adoptTenant(database, schema, fixture.tenant, [{ kind: 'user', resourceId: id }]); return id;
}
function wrapped(operation) { return { ...database, transaction: (callback, options) => database.transaction(async client => { const result = await callback(client); await operation(client); return result; }, options) }; }
test('a real canonical user can join two own units without a new role, license or department rewrite', async () => {
  const fixture = await actor(); const first = await create(fixture, 'Engineering'); const second = await create(fixture, 'Operations'); const userId = await person(fixture);
  const firstLink = await add(fixture, first, userId); const secondLink = await add(fixture, second, userId); assert.notEqual(firstLink.membership.id, secondLink.membership.id); assert.equal(firstLink.unit.memberCount, 1); assert.equal(secondLink.unit.memberCount, 1);
  const result = await page(fixture, first); assert.equal(result.total, 1); assert.equal(result.profileAccess, false); assert.equal(result.members[0].profile, undefined); assert.equal(result.members[0].userId, userId);
  assert.equal((await pool.query('SELECT department FROM users WHERE id=$1', [userId])).rows[0].department, 'Preserved external department'); assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_role_assignments WHERE user_id=$1', [userId])).rows[0].count, 0);
  const recorded = await events(); assert.deepEqual(recorded.map(event => event.type), ['organization-unit.member.added', 'organization-unit.member.added']); assert.equal(recorded[0].proof.target.member.id, firstLink.membership.id); assert.equal(recorded[0].actor.userId, fixture.id); assert.equal(recorded[0].correlation_id, recorded[0].id); assert.equal(recorded[0].status, 'pending');
});
test('membership profile data requires independent user-read authority rather than membership-management duty', async () => {
  const fixture = await actor(); let unit = await create(fixture); const userId = await person(fixture, 'Actual Named Employee'); unit = (await add(fixture, unit, userId)).unit;
  const reader = await actor('directory-reader', fixture.tenant); const result = await page(reader, unit); assert.equal(result.profileAccess, true); assert.equal(result.members[0].profile.displayName, 'Actual Named Employee');
  assert.equal((await page(fixture, unit)).members[0].profile, undefined); await assert.rejects(add(reader, unit, userId), error => error.status === 403);
});
test('duplicate and stale assignments never create a second active pair or an extra event', async () => {
  const fixture = await actor(); const unit = await create(fixture); const userId = await person(fixture); const linked = await add(fixture, unit, userId);
  await assert.rejects(add(fixture, unit, userId), error => error.status === 412); await assert.rejects(add(fixture, linked.unit, userId), error => error.status === 409); assert.equal((await events()).length, 1); assert.equal((await page(fixture, linked.unit)).total, 1);
});
test('removal preserves its exact old incarnation and re-adding creates a fresh link without resurrecting the former ID', async () => {
  const fixture = await actor(); const unit = await create(fixture); const userId = await person(fixture); const first = await add(fixture, unit, userId); const removed = await unlink(fixture, first); assert.equal(removed.action, 'member-remove'); assert.equal(removed.unit.memberCount, 0);
  const second = await add(fixture, removed.unit, userId); assert.notEqual(second.membership.id, first.membership.id); await assert.rejects(fixture.mutator.removeMember(unit.id, first.membership.id, ouEtag(second.unit), fixture.user, 'Bearer original'), error => error.status === 404);
  const recorded = await events(); assert.equal(recorded[1].proof.target.member.before.id, first.membership.id); assert.equal(recorded[1].type, 'organization-unit.member.removed'); assert.equal(recorded.length, 3);
});
test('foreign units, users and membership IDs cannot be resolved through own-tenant management', async () => {
  const fixture = await actor('admin'); const other = await actor(); const own = await create(fixture); const foreign = await create(other); const ownUser = await person(fixture); const foreignUser = await person(other); const foreignLink = await add(other, foreign, foreignUser);
  await assert.rejects(add(fixture, foreign, ownUser), error => error.status === 404); await assert.rejects(add(fixture, own, foreignUser), error => error.status === 404); await assert.rejects(page(fixture, foreign), error => error.status === 404);
  await assert.rejects(fixture.mutator.removeMember(own.id, foreignLink.membership.id, ouEtag(own), fixture.user, 'Bearer original'), error => error.status === 404); assert.equal((await events()).length, 1);
});
test('a fresh ordinary human gets no target-existence oracle before membership authorization', async () => {
  const fixture = await actor(); const unit = await create(fixture); const userId = await person(fixture); const ordinary = await actor('user', fixture.tenant);
  for (const target of [userId, randomUUID()]) await assert.rejects(add(ordinary, unit, target), error => error.status === 403); assert.equal((await events()).length, 0);
});
test('active links block both OU and canonical-user deletion until their controlled removal', async () => {
  const fixture = await actor('admin'); const unit = await create(fixture); const userId = await person(fixture); const linked = await add(fixture, unit, userId);
  const { UserMutator } = require('../UserMutator'); const { userEtag } = require('../DirectoryUsers'); const users = new UserMutator(database, fixture.options); const account = await fixture.reader.user(userId, {}, fixture.user, 'Bearer original');
  await assert.rejects(fixture.mutator.remove(unit.id, ouEtag(linked.unit), fixture.user, 'Bearer original'), error => error.status === 409);
  await assert.rejects(users.remove(userId, userEtag(account), fixture.user, 'Bearer original'), error => error.status === 409 && error.message === 'user_has_organization_memberships');
  const removed = await unlink(fixture, linked); await fixture.mutator.remove(unit.id, ouEtag(removed.unit), fixture.user, 'Bearer original'); await users.remove(userId, userEtag(account), fixture.user, 'Bearer original'); assert.equal((await events()).length, 3);
});
test('membership pages are real bounded repeatable snapshots with exact counts and version', async () => {
  const fixture = await actor(); let unit = await create(fixture);
  for (let index = 0; index < 27; index++) unit = (await add(fixture, unit, await person(fixture, 'Employee ' + index))).unit;
  const first = await page(fixture, unit, { page: '1', limit: '25' }); const second = await page(fixture, unit, { page: '2', limit: '25' }); assert.equal(first.total, 27); assert.equal(first.members.length, 25); assert.equal(second.members.length, 2); assert.equal(second.unit.revision, first.unit.revision); assert.equal(new Set([...first.members, ...second.members].map(link => link.id)).size, 27);
  await assert.rejects(page(fixture, unit, { tenantId: fixture.tenant }), error => error.status === 400);
});
test('late original-token withdrawal rolls link, OU version, event and outbox back together', async () => {
  const fixture = await actor(); const unit = await create(fixture); const userId = await person(fixture); fixture.live.checks = 0; fixture.live.onCheck = async count => { if (count === 3) fixture.live.revoked = true; };
  await assert.rejects(add(fixture, unit, userId), error => error.status === 401); fixture.live.revoked = false; fixture.live.onCheck = null; assert.deepEqual(await read(fixture, unit), unit); assert.equal((await events()).length, 0); assert.equal((await page(fixture, unit)).total, 0);
});
test('physical proof expiry at actual commit cannot retain a received membership', { timeout: 15000 }, async () => {
  const fixture = await actor(); const unit = await create(fixture); const userId = await person(fixture); fixture.user.exp = Math.floor(Date.now() / 1000) + 2; beforeCommit = async () => { await new Promise(resolve => setTimeout(resolve, 2200)); };
  await assert.rejects(add(fixture, unit, userId), error => ['42501', '28000'].includes(error.code)); beforeCommit = null; assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_directory_ou_members')).rows[0].count, 0); assert.equal((await events()).length, 0);
});
test('cleared scopes and unrelated writes cannot ride an admitted membership transition', async () => {
  const fixture = await actor(); const unit = await create(fixture); const userId = await person(fixture);
  for (const sql of ["UPDATE users SET title='Unrelated'", 'TRUNCATE groups CASCADE']) {
    const mutator = new OuMutator(wrapped(async client => { await client.query("SELECT set_config('opendirectory.ou_mutation','',true)"); await client.query(sql); }), fixture.options);
    await assert.rejects(mutator.addMember(unit.id, { userId }, ouEtag(unit), fixture.user, 'Bearer original'), error => error.code === '42501'); assert.equal((await events()).length, 0);
  }
});
test('missing row or deferred receivers prevent positive membership admission', async () => {
  const fixture = await actor(); const unit = await create(fixture); const userId = await person(fixture);
  for (const trigger of ['identity_directory_ou_member_guard', 'identity_directory_ou_member_commit']) {
    await pool.query('ALTER TABLE identity_directory_ou_members DISABLE TRIGGER ' + trigger);
    try { await assert.rejects(add(fixture, unit, userId), error => error.status === 503); } finally { await pool.query('ALTER TABLE identity_directory_ou_members ENABLE TRIGGER ' + trigger); }
  }
  assert.equal((await events()).length, 0);
});
test('omitted membership, event or outbox cannot produce a successful command receipt', async () => {
  const fixture = await actor(); const unit = await create(fixture); const userId = await person(fixture);
  for (const table of ['identity_directory_ou_members', 'identity_directory_ou_events', 'identity_directory_ou_outbox']) {
    await pool.query('CREATE FUNCTION omit_member_receipt() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL;END; $$;CREATE TRIGGER zzzz_omit_member_receipt BEFORE INSERT ON ' + table + ' FOR EACH ROW EXECUTE FUNCTION omit_member_receipt()');
    try { await assert.rejects(add(fixture, unit, userId), error => error.status === 503 || error.code === '23514'); } finally { await pool.query('DROP TRIGGER zzzz_omit_member_receipt ON ' + table + ';DROP FUNCTION omit_member_receipt()'); }
    assert.equal((await events()).length, 0); assert.deepEqual(await read(fixture, unit), unit);
  }
});
test('membership metadata cannot be rewritten by a late row trigger after admission', async () => {
  const fixture = await actor(); const unit = await create(fixture); const userId = await person(fixture);
  await pool.query("CREATE FUNCTION drift_member_receipt() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN NEW.created_at=NEW.created_at+interval '1 second';RETURN NEW;END; $$;CREATE TRIGGER zzzz_drift_member_receipt BEFORE INSERT ON identity_directory_ou_members FOR EACH ROW EXECUTE FUNCTION drift_member_receipt()");
  try { await assert.rejects(add(fixture, unit, userId), error => error.code === '23514'); } finally { await pool.query('DROP TRIGGER zzzz_drift_member_receipt ON identity_directory_ou_members;DROP FUNCTION drift_member_receipt()'); }
  assert.equal((await events()).length, 0);
});
test('a deliberately corrupted cross-tenant link fails closed instead of exposing another company profile', async () => {
  const fixture = await actor('admin'); const foreign = await actor(); const unit = await create(fixture); const userId = await person(foreign);
  await pool.query('ALTER TABLE identity_directory_ou_members DISABLE TRIGGER identity_directory_ou_member_guard;ALTER TABLE identity_directory_ou_members DISABLE TRIGGER identity_directory_ou_member_commit');
  try { await pool.query('INSERT INTO identity_directory_ou_members VALUES($1,$2,$3,$4,clock_timestamp())', [randomUUID(), fixture.tenant, unit.id, userId]); }
  finally { await pool.query('ALTER TABLE identity_directory_ou_members ENABLE TRIGGER identity_directory_ou_member_guard;ALTER TABLE identity_directory_ou_members ENABLE TRIGGER identity_directory_ou_member_commit'); }
  await assert.rejects(page(fixture, unit), error => error.status === 503); await assert.rejects(read(fixture, unit), error => error.status === 503);
});
test('migration replay and caller timezones preserve exact membership evidence and current pages', async () => {
  const fixture = await actor('admin'); const unit = await create(fixture); const userId = await person(fixture); const linked = await add(fixture, unit, userId); const before = await page(fixture, linked.unit); const recorded = await events();
  await pool.query(fs.readFileSync(path.join(migrations, '043_ou_memberships.sql'), 'utf8')); await pool.query("SET timezone='Pacific/Honolulu'"); assert.deepEqual(await page(fixture, linked.unit), before); assert.deepEqual(await events(), recorded);
});
function holdNextCommit() {
  let readySignal; let release; let held = true; const ready = new Promise(resolve => { readySignal = resolve; }); const gate = new Promise(resolve => { release = resolve; });
  beforeCommit = async () => { if (held) { held = false; readySignal(); await gate; } }; return { ready, release: () => release() };
}
function observedDatabase() {
  let startedSignal; const started = new Promise(resolve => { startedSignal = resolve; });
  return { started, database: { ...database, transaction: (callback, options) => database.transaction(async client => { startedSignal((await client.query('SELECT pg_backend_pid() AS pid')).rows[0].pid); return callback(client); }, options) } };
}
async function waitForLock(pid) {
  const until = Date.now() + 2000;
  while (Date.now() < until) { if ((await pool.query("SELECT wait_event_type='Lock' AS waiting FROM pg_stat_activity WHERE pid=$1", [pid])).rows[0]?.waiting) return; await new Promise(resolve => setTimeout(resolve, 10)); }
  assert.fail('Expected an observed wait by the exact competing database session');
}
test('actual simultaneous additions serialize and reject the second stale OU version', { timeout: 15000 }, async () => {
  const fixture = await actor(); const unit = await create(fixture); const firstUser = await person(fixture); const secondUser = await person(fixture); const gate = holdNextCommit(); const first = add(fixture, unit, firstUser); await gate.ready;
  const observed = observedDatabase(); const second = assert.rejects(new OuMutator(observed.database, fixture.options).addMember(unit.id, { userId: secondUser }, ouEtag(unit), fixture.user, 'Bearer original'), error => error.status === 412);
  try { await waitForLock(await observed.started); } finally { gate.release(); } await first; await second; beforeCommit = null; assert.equal((await page(fixture, unit)).total, 1); assert.equal((await events()).length, 1);
});
test('membership admission before a waiting OU deletion invalidates its old version and preserves the actual dependency', { timeout: 15000 }, async () => {
  const fixture = await actor(); const unit = await create(fixture); const userId = await person(fixture); const gate = holdNextCommit(); const adding = add(fixture, unit, userId); await gate.ready;
  const observed = observedDatabase(); const deleting = assert.rejects(new OuMutator(observed.database, fixture.options).remove(unit.id, ouEtag(unit), fixture.user, 'Bearer original'), error => error.status === 412);
  try { await waitForLock(await observed.started); } finally { gate.release(); } const linked = await adding; await deleting; beforeCommit = null;
  await assert.rejects(fixture.mutator.remove(unit.id, ouEtag(linked.unit), fixture.user, 'Bearer original'), error => error.status === 409); assert.equal((await page(fixture, unit)).total, 1);
});
test('an actual canonical-user deletion waiting on membership admission cannot remove its new active dependency', { timeout: 15000 }, async () => {
  const fixture = await actor('admin'); const unit = await create(fixture); const userId = await person(fixture); const account = await fixture.reader.user(userId, {}, fixture.user, 'Bearer original'); const gate = holdNextCommit(); const adding = add(fixture, unit, userId); await gate.ready;
  const observed = observedDatabase(); const { UserMutator } = require('../UserMutator'); const { userEtag } = require('../DirectoryUsers');
  const deleting = assert.rejects(new UserMutator(observed.database, fixture.options).remove(userId, userEtag(account), fixture.user, 'Bearer original'), error => error.status === 409);
  try { await waitForLock(await observed.started); } finally { gate.release(); } await adding; await deleting; beforeCommit = null; assert.equal((await page(fixture, unit)).total, 1);
});
test('a user deleted before a waiting membership operation cannot become a new dangling link', { timeout: 15000 }, async () => {
  const fixture = await actor('admin'); const unit = await create(fixture); const userId = await person(fixture); const account = await fixture.reader.user(userId, {}, fixture.user, 'Bearer original'); const { UserMutator } = require('../UserMutator'); const { userEtag } = require('../DirectoryUsers'); const gate = holdNextCommit();
  const deleting = new UserMutator(database, fixture.options).remove(userId, userEtag(account), fixture.user, 'Bearer original'); await gate.ready;
  const observed = observedDatabase(); const adding = assert.rejects(new OuMutator(observed.database, fixture.options).addMember(unit.id, { userId }, ouEtag(unit), fixture.user, 'Bearer original'), error => error.status === 404);
  try { await waitForLock(await observed.started); } finally { gate.release(); } await deleting; await adding; beforeCommit = null; assert.equal((await page(fixture, unit)).total, 0); assert.equal((await events()).length, 0);
});
test('a retained membership UUID cannot be reused by another otherwise current private admission', async () => {
  const fixture = await actor(); const unit = await create(fixture); const userId = await person(fixture); const first = await add(fixture, unit, userId); await unlink(fixture, first); const recorded = await events(); const previous = recorded[1];
  const proof = { ...previous.proof, operationId: randomUUID(), target: { ...previous.proof.target, action: 'member-add', before: previous.after_state, member: { id: first.membership.id, userId, before: null } } };
  await assert.rejects(database.transaction(client => client.query('SELECT identity_directory_ou_membership_change($1::jsonb)', [JSON.stringify(proof)])), error => error.code === '23514'); assert.equal((await events()).length, 2); assert.equal((await page(fixture, unit)).total, 0);
});
test('raw writes and an actual limited SQL login or SET ROLE cannot substitute a membership command', async () => {
  const fixture = await actor(); const unit = await create(fixture); const userId = await person(fixture);
  await assert.rejects(pool.query('INSERT INTO identity_directory_ou_members VALUES($1,$2,$3,$4,clock_timestamp())', [randomUUID(), fixture.tenant, unit.id, userId]), error => error.code === '42501');
  const role = 'member_limited_' + randomUUID().replaceAll('-', ''); let limited;
  try {
    await administration.query('CREATE ROLE ' + role + ' LOGIN'); await pool.query('GRANT USAGE ON SCHEMA ' + schema + ' TO ' + role + ';GRANT EXECUTE ON FUNCTION identity_directory_ou_membership_change(jsonb) TO ' + role);
    const address = new URL(process.env.IDENTITY_TEST_DATABASE_URL); address.username = role; limited = new Pool({ connectionString: address.toString(), options: `-c search_path=${schema},public`, max: 1 });
    for (const assumed of [false, true]) { const client = await (assumed ? pool : limited).connect();
      try { await client.query('BEGIN'); if (assumed) await client.query('SET LOCAL ROLE ' + role); await assert.rejects(client.query('SELECT identity_directory_ou_membership_change($1::jsonb)', ['{}']), error => error.code === '42501' && error.message.includes('Actual database owner required')); }
      finally { await client.query('ROLLBACK'); client.release(); }
    }
  } finally { await limited?.end(); await pool.query('DROP OWNED BY ' + role); await administration.query('DROP ROLE ' + role); }
});
