'use strict';

const { test, before, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { Pool } = require('pg');
const { AuthorizationState } = require('../AuthorizationState');
const { DirectoryRoles } = require('../DirectoryRoles');
const { PrivilegedActivation } = require('../PrivilegedActivation');
const { bootstrapRole } = require('../../scripts/bootstrap-role');
const { provisionTenant, adoptTenant, enableTenant } = require('../../../../../scripts/lib/tenant-ownership-fixture.cjs');

const schema = 'authority_targets_' + randomUUID().replaceAll('-', '');
const administration = new Pool({ connectionString: process.env.IDENTITY_TEST_DATABASE_URL, max: 1 });
const issuer = 'https://authority-target.test';
const migrations = path.join(__dirname, '../../migrations');
const reason = 'Explicit same-owner finite role and PIM target verification';
let pool; let database; let roles; let pim;
before(async () => {
  await administration.query('CREATE SCHEMA ' + schema);
  pool = new Pool({ connectionString: process.env.IDENTITY_TEST_DATABASE_URL, max: 8, options: `-c search_path=${schema},public` });
  database = { isAvailable: () => true, getClient: () => pool.connect(), query: (...args) => pool.query(...args), transaction: async (operation, options = {}) => {
    const client = await pool.connect();
    try {
      await client.query(options.readOnly ? 'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY' : 'BEGIN'); await client.query("SET LOCAL lock_timeout='5s';SET LOCAL statement_timeout='15s'");
      if (options.actor) await client.query("SELECT set_config('opendirectory.actor',$1,true)", [options.actor]);
      const result = await operation(client); await client.query('COMMIT'); return result;
    } catch (error) { await client.query('ROLLBACK'); throw error; } finally { client.release(); }
  } };
  for (const file of fs.readdirSync(migrations).filter(file => file.endsWith('.sql')).sort()) await pool.query(fs.readFileSync(path.join(migrations, file), 'utf8'));
  roles = new DirectoryRoles(database, { revalidate: async () => {} }); pim = new PrivilegedActivation(database, { revalidate: async () => {} });
});
beforeEach(async () => { await pool.query('TRUNCATE identity_tenants,users,groups,ous,identity_role_review_policies,identity_role_assignments,identity_pim_eligibilities CASCADE'); });
after(async () => { await pool.end(); await administration.query('DROP SCHEMA ' + schema + ' CASCADE'); await administration.end(); });
function actor(person) { return JSON.stringify({ issuer, subject: person.user.sub, ...person.user.identity_authorization }); }
async function person(role = 'user', tenant) {
  tenant = tenant || await provisionTenant(database, schema, { enabled: true }); const userId = randomUUID(); const subject = 'authority-target-' + randomUUID();
  await pool.query('INSERT INTO users(id,username,email) VALUES($1,$2,$3)', [userId, subject, subject + '@test.invalid']);
  await pool.query('INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES($1,$2,$3)', [issuer, subject, userId]); await adoptTenant(database, schema, tenant, [{ kind: 'user', resourceId: userId }]);
  await bootstrapRole(database, { userId, role, duration: 3600, reason }); const state = await new AuthorizationState(database).state(issuer, subject);
  return { userId, tenant, user: { actor_type: 'user', iss: issuer, sub: subject, roles: state.roles, identity_authorization: state.context, jti: randomUUID(), exp: Math.floor(Date.now() / 1000) + 300 } };
}
async function eligibility(operator, recipient) {
  return pim.grantEligibility({ userId: recipient.userId, role: 'license-manager', maxDurationSeconds: 300, validForSeconds: 3600, reason }, operator.user);
}
async function request(recipient, eligible) { return pim.request({ id: randomUUID(), eligibilityId: eligible.id, durationSeconds: 300, reason }, recipient.user); }
async function evidence() {
  return (await pool.query(`SELECT (SELECT count(*)::int FROM identity_role_assignments) AS assignments,(SELECT count(*)::int FROM identity_pim_eligibilities) AS eligibilities,
    (SELECT count(*)::int FROM identity_pim_requests) AS requests,(SELECT count(*)::int FROM identity_role_audit) AS role_audit,(SELECT count(*)::int FROM identity_pim_audit) AS pim_audit`)).rows[0];
}
test('actual same-tenant role delegation still uses current operator roles and retains canonical origin evidence', async () => {
  const operator = await person('role-administrator'); const recipient = await person('user', operator.tenant);
  const granted = await roles.grant(recipient.userId, { role: 'license-manager', durationSeconds: 300, reason }, operator.user); assert.equal(granted.status, 'active');
  assert.deepEqual((await new AuthorizationState(database).state(issuer, recipient.user.sub)).roles, ['license-manager', 'user']);
  await roles.revoke(recipient.userId, granted.id, operator.user); assert.deepEqual((await new AuthorizationState(database).state(issuer, recipient.user.sub)).roles, ['user']);
  const audit = (await pool.query('SELECT actor FROM identity_role_audit WHERE assignment_id=$1', [granted.id])).rows; assert.equal(audit.length, 2); assert.ok(audit.every(row => JSON.parse(row.actor).userId === operator.userId));
});
test('even an actual global administrator cannot grant or revoke a foreign canonical user source', async () => {
  const operator = await person('admin'); const foreign = await person('admin'); const recipient = await person('user', foreign.tenant);
  const granted = await roles.grant(recipient.userId, { role: 'license-manager', durationSeconds: 300, reason }, foreign.user); const before = await evidence(); const state = await new AuthorizationState(database).state(issuer, recipient.user.sub);
  await assert.rejects(roles.grant(recipient.userId, { role: 'license-manager', durationSeconds: 300, reason }, operator.user), error => error.status === 404);
  await assert.rejects(roles.revoke(recipient.userId, granted.id, operator.user), error => error.status === 404); assert.deepEqual(await evidence(), before); assert.deepEqual(await new AuthorizationState(database).state(issuer, recipient.user.sub), state);
});
test('foreign user locks are not acquired or waited on before role or eligibility target rejection', async () => {
  const operator = await person('admin'); const foreign = await person(); const blocker = await pool.connect();
  try {
    await blocker.query('BEGIN'); await blocker.query('SELECT id FROM users WHERE id=$1 FOR UPDATE', [foreign.userId]); const started = Date.now();
    await assert.rejects(roles.grant(foreign.userId, { role: 'license-manager', durationSeconds: 300, reason }, operator.user), error => error.status === 404);
    await assert.rejects(eligibility(operator, foreign), error => error.status === 404); assert.ok(Date.now() - started < 2000);
  } finally { await blocker.query('ROLLBACK'); blocker.release(); }
});
test('known foreign eligibility and request UUIDs stay absent across every role-bearing PIM transition', async () => {
  const operator = await person('admin'); const foreign = await person('admin'); const recipient = await person('user', foreign.tenant); const eligible = await eligibility(foreign, recipient); const pending = await request(recipient, eligible); const before = await evidence();
  await assert.rejects(pim.eligibilities(recipient.userId, operator.user), error => error.status === 404); await assert.rejects(eligibility(operator, recipient), error => error.status === 404);
  await assert.rejects(pim.revokeEligibility(eligible.id, operator.user), error => error.status === 404);
  await assert.rejects(pim.request({ id: randomUUID(), eligibilityId: eligible.id, durationSeconds: 300, reason }, operator.user), error => error.status === 404);
  for (const action of ['approve', 'deny', 'activate', 'cancel', 'revoke']) await assert.rejects(pim.change(pending.id, action, operator.user), error => error.status === 404);
  assert.deepEqual(await evidence(), before);
});
test('the actual PIM queue filters ownership before its SQL limit and does not spend the result budget on foreign pending requests', async () => {
  const operator = await person('admin'); const recipient = await person('user', operator.tenant); const own = await request(recipient, await eligibility(operator, recipient));
  const foreign = await person('admin'); const foreignRecipient = await person('user', foreign.tenant); const eligible = await eligibility(foreign, foreignRecipient);
  await database.transaction(client => client.query(`INSERT INTO identity_pim_requests(id,eligibility_id,user_id,reason,duration_seconds,request_authority,deadline_at)
    SELECT gen_random_uuid(),$1,$2,$3,300,$4,clock_timestamp()+interval '10 minutes' FROM generate_series(1,110)`, [eligible.id, foreignRecipient.userId, reason, actor(foreignRecipient)]), { actor: actor(foreignRecipient) });
  const ownQueue = await pim.queue(operator.user); assert.equal(ownQueue.truncated, false); assert.deepEqual(ownQueue.requests.map(row => row.id), [own.id]);
  const foreignQueue = await pim.queue(foreign.user); assert.equal(foreignQueue.truncated, true); assert.equal(foreignQueue.requests.length, 100); assert.ok(foreignQueue.requests.every(row => row.userId === foreignRecipient.userId));
});
test('the SQL receiving trigger rejects coherent foreign canonical role and eligibility writes even outside the JavaScript classes', async () => {
  const operator = await person('admin'); const foreign = await person(); const before = await evidence();
  for (const sql of ["INSERT INTO identity_role_assignments(user_id,role,reason,expires_at) VALUES($1,'license-manager',$2,clock_timestamp()+interval '5 minutes')",
    "INSERT INTO identity_pim_eligibilities(user_id,role,reason,max_duration_seconds,expires_at) VALUES($1,'license-manager',$2,300,clock_timestamp()+interval '1 hour')"])
    await assert.rejects(database.transaction(client => client.query(sql, [foreign.userId, reason]), { actor: actor(operator) }), error => error.code === '23503');
  assert.deepEqual(await evidence(), before);
});
test('SQL cannot save a foreign approver or requester into an otherwise same-tenant pending PIM source', async () => {
  const operator = await person('admin'); const recipient = await person('user', operator.tenant); const foreign = await person('admin'); const eligible = await eligibility(operator, recipient); const pending = await request(recipient, eligible);
  await assert.rejects(database.transaction(client => client.query("UPDATE identity_pim_requests SET state='approved',decision_authority=$2 WHERE id=$1", [pending.id, actor(foreign)]), { actor: actor(operator) }), error => error.code === '23503');
  await assert.rejects(database.transaction(client => client.query("INSERT INTO identity_pim_requests(id,eligibility_id,user_id,reason,duration_seconds,request_authority,deadline_at) VALUES($1,$2,$3,$4,300,$5,clock_timestamp()+interval '10 minutes')", [randomUUID(), eligible.id, recipient.userId, reason, actor(foreign)]), { actor: actor(recipient) }), error => error.code === '23503');
  assert.equal((await pool.query('SELECT state FROM identity_pim_requests WHERE id=$1', [pending.id])).rows[0].state, 'pending');
});
test('canonical review capture cannot attach a foreign voter to an owned assignment through a global legacy policy', async () => {
  const operator = await person('admin'); const recipient = await person('user', operator.tenant); const foreign = await person('access-reviewer');
  await roles.grant(recipient.userId, { role: 'license-manager', durationSeconds: 300, reason }, operator.user);
  await assert.rejects(database.transaction(async client => { await client.query("SELECT set_config('opendirectory.review_reason',$1,true)", [reason]); await client.query("INSERT INTO identity_role_review_policies(role,interval_seconds,window_seconds,reviewer_user_ids) VALUES('license-manager',3600,300,$1)", [[foreign.userId]]); }, { actor: actor(operator) }), error => error.code === '23503');
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_role_review_policies')).rows[0].count, 0); assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_role_review_leases')).rows[0].count, 0);
});
test('missing receiving guards fail before role and PIM mutation instead of falling back to the old unscoped receiver', async () => {
  const operator = await person('admin'); const recipient = await person('user', operator.tenant); const before = await evidence();
  for (const relation of ['identity_role_assignments', 'identity_pim_eligibilities', 'identity_pim_requests', 'identity_role_review_leases']) {
    await pool.query('ALTER TABLE ' + relation + ' DISABLE TRIGGER aaa_identity_authority_target_tenant');
    try { await assert.rejects(roles.grant(recipient.userId, { role: 'license-manager', durationSeconds: 300, reason }, operator.user), error => error.status === 503); await assert.rejects(eligibility(operator, recipient), error => error.status === 503); }
    finally { await pool.query('ALTER TABLE ' + relation + ' ENABLE TRIGGER aaa_identity_authority_target_tenant'); }
  }
  assert.deepEqual(await evidence(), before);
});
test('actor home requires the real enabled link mapping, current generations and enabled retained tenant, not a supplied user ID alone', async () => {
  const operator = await person('admin'); const recipient = await person('user', operator.tenant); const other = await person('admin', operator.tenant);
  await assert.rejects(roles.grant(recipient.userId, { role: 'license-manager', durationSeconds: 300, reason }, { ...operator.user, sub: other.user.sub }), error => error.status === 401);
  await pool.query('UPDATE users SET authorization_revision=authorization_revision+1 WHERE id=$1', [operator.userId]);
  await assert.rejects(eligibility(operator, recipient), error => error.status === 401); await enableTenant(database, schema, operator.tenant, false);
  await assert.rejects(pim.queue(other.user), error => error.status === 401);
});
test('source-fence replay preserves actual role IDs, existing authority generations and all retained audit evidence', async () => {
  const operator = await person('admin'); const recipient = await person('user', operator.tenant); const granted = await roles.grant(recipient.userId, { role: 'license-manager', durationSeconds: 300, reason }, operator.user);
  const before = await evidence(); const state = await new AuthorizationState(database).state(issuer, recipient.user.sub); await pool.query(fs.readFileSync(path.join(migrations, '032_authority_target_tenants.sql'), 'utf8'));
  assert.deepEqual(await evidence(), before); assert.deepEqual(await new AuthorizationState(database).state(issuer, recipient.user.sub), state); assert.equal((await pool.query('SELECT id FROM identity_role_assignments WHERE id=$1', [granted.id])).rows[0].id, granted.id);
});
test('an actual limited login or assumed role cannot launder a raw offline write or canonical proof through the receiving trigger', async () => {
  const operator = await person('admin'); const recipient = await person('user', operator.tenant); const role = 'authority_target_limited_' + randomUUID().replaceAll('-', ''); let limited;
  await administration.query(`CREATE ROLE ${role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS`);
  try {
    await pool.query(`GRANT USAGE ON SCHEMA ${schema} TO ${role};GRANT INSERT ON identity_role_assignments TO ${role}`);
    const address = new URL(process.env.IDENTITY_TEST_DATABASE_URL); address.username = role; limited = new Pool({ connectionString: address.toString(), max: 1, options: `-c search_path=${schema},public` });
    for (const assumed of [false, true]) for (const proof of ['database', actor(operator)]) {
      const client = await (assumed ? pool : limited).connect();
      try {
        await client.query('BEGIN'); if (assumed) await client.query('SET LOCAL ROLE ' + role); await client.query("SELECT set_config('opendirectory.actor',$1,true)", [proof]);
        await assert.rejects(client.query("INSERT INTO identity_role_assignments(user_id,role,reason,expires_at) VALUES($1,'license-manager',$2,clock_timestamp()+interval '5 minutes')", [recipient.userId, reason]), error => error.code === '42501' && error.message === 'Actual receiving database owner required for legacy authority writes');
      } finally { await client.query('ROLLBACK'); client.release(); }
    }
  } finally { await limited?.end(); await pool.query('DROP OWNED BY ' + role); await administration.query('DROP ROLE ' + role); }
});
test('physical operator role expiry during an observed owned-user lock wait prevents a stale direct grant', async () => {
  const operator = await person(); const administrator = await person('admin', operator.tenant); const recipient = await person('user', operator.tenant);
  await database.transaction(client => client.query("INSERT INTO identity_role_assignments(user_id,role,reason,expires_at) VALUES($1,'role-administrator',$2,clock_timestamp()+interval '2 seconds')", [operator.userId, reason]), { actor: actor(administrator) });
  const state = await new AuthorizationState(database).state(issuer, operator.user.sub); operator.user.roles = state.roles; operator.user.identity_authorization = state.context;
  const blocker = await pool.connect(); let pending;
  try {
    await blocker.query('BEGIN'); const backend = (await blocker.query('SELECT pg_backend_pid() AS id')).rows[0].id; await blocker.query('SELECT id FROM users WHERE id=$1 FOR UPDATE', [recipient.userId]);
    pending = roles.grant(recipient.userId, { role: 'license-manager', durationSeconds: 300, reason }, operator.user); pending.catch(() => {}); let waiting = false;
    for (let attempt = 0; attempt < 200; attempt++) { waiting = (await pool.query("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(pid))) AS waiting", [backend])).rows[0].waiting; if (waiting) break; await new Promise(resolve => setTimeout(resolve, 5)); }
    assert.equal(waiting, true); await blocker.query('SELECT pg_sleep(2.1)'); await blocker.query('ROLLBACK'); await assert.rejects(pending, error => error.status === 401);
  } finally { await blocker.query('ROLLBACK'); blocker.release(); if (pending) await pending.catch(() => {}); }
  assert.equal((await pool.query("SELECT count(*)::int AS count FROM identity_role_assignments WHERE user_id=$1 AND role='license-manager'", [recipient.userId])).rows[0].count, 0);
});
test('an owner can cancel an imported foreign approval without admitting it or taking the historical foreign decision user lock', async () => {
  const operator = await person('admin'); const recipient = await person('user', operator.tenant); const foreign = await person('pim-approver');
  const pending = await request(recipient, await eligibility(operator, recipient));
  await pool.query('ALTER TABLE identity_pim_requests DISABLE TRIGGER aaa_identity_authority_target_tenant');
  try { await database.transaction(client => client.query("UPDATE identity_pim_requests SET state='approved',decision_authority=$2 WHERE id=$1", [pending.id, actor(foreign)]), { actor: actor(foreign) }); }
  finally { await pool.query('ALTER TABLE identity_pim_requests ENABLE TRIGGER aaa_identity_authority_target_tenant'); }
  const imported = (await pool.query('SELECT decided_at,decision_authority FROM identity_pim_requests WHERE id=$1', [pending.id])).rows[0];
  const blocker = await pool.connect();
  try {
    await blocker.query('BEGIN'); await blocker.query('SELECT id FROM users WHERE id=$1 FOR UPDATE', [foreign.userId]); const started = Date.now();
    await assert.rejects(pim.change(pending.id, 'activate', recipient.user), error => error.status === 404);
    const cancelled = await pim.change(pending.id, 'cancel', recipient.user); assert.equal(cancelled.status, 'cancelled'); assert.ok(Date.now() - started < 2000);
  } finally { await blocker.query('ROLLBACK'); blocker.release(); }
  const retained = (await pool.query('SELECT state,decided_at,decision_authority FROM identity_pim_requests WHERE id=$1', [pending.id])).rows[0];
  assert.equal(retained.state, 'cancelled'); assert.deepEqual(retained.decided_at, imported.decided_at); assert.deepEqual(retained.decision_authority, imported.decision_authority);
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_role_assignments WHERE activation_request_id=$1', [pending.id])).rows[0].count, 0);
});
test('same-tenant cleanup can revoke an imported foreign-origin role without locking or rewriting its historical grantor', async () => {
  const operator = await person('role-administrator'); const recipient = await person('user', operator.tenant); const foreign = await person('admin'); let grant;
  await pool.query('ALTER TABLE identity_role_assignments DISABLE TRIGGER aaa_identity_authority_target_tenant');
  try { grant = await database.transaction(async client => (await client.query("INSERT INTO identity_role_assignments(user_id,role,reason,expires_at) VALUES($1,'license-manager',$2,clock_timestamp()+interval '5 minutes') RETURNING id", [recipient.userId, reason])).rows[0], { actor: actor(foreign) }); }
  finally { await pool.query('ALTER TABLE identity_role_assignments ENABLE TRIGGER aaa_identity_authority_target_tenant'); }
  assert.ok((await new AuthorizationState(database).state(issuer, recipient.user.sub)).roles.includes('license-manager'));
  const original = (await pool.query("SELECT actor,details FROM identity_role_audit WHERE assignment_id=$1 AND action='granted'", [grant.id])).rows[0]; const blocker = await pool.connect();
  try {
    await blocker.query('BEGIN'); await blocker.query('SELECT id FROM users WHERE id=$1 FOR UPDATE', [foreign.userId]); const started = Date.now();
    assert.equal((await roles.revoke(recipient.userId, grant.id, operator.user)).revoked, true); assert.ok(Date.now() - started < 2000);
  } finally { await blocker.query('ROLLBACK'); blocker.release(); }
  assert.deepEqual((await new AuthorizationState(database).state(issuer, recipient.user.sub)).roles, ['user']);
  assert.deepEqual((await pool.query("SELECT actor,details FROM identity_role_audit WHERE assignment_id=$1 AND action='granted'", [grant.id])).rows[0], original);
  assert.equal(JSON.parse((await pool.query("SELECT actor FROM identity_role_audit WHERE assignment_id=$1 AND action='revoked'", [grant.id])).rows[0].actor).userId, operator.userId);
});
