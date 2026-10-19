'use strict';

const { test, before, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { Pool } = require('pg');
const { DirectoryRoles } = require('../DirectoryRoles');
const { RoleAuthentication, policyEtag } = require('../RoleAuthentication');
const { PrivilegedAccessPolicy, activationEtag } = require('../PrivilegedAccessPolicy');
const { RoleReviews } = require('../RoleReviews');
const { AuthorizationState } = require('../AuthorizationState');
const { bootstrapRole } = require('../../scripts/bootstrap-role');
const { provisionTenant, adoptTenant } = require('../../../../../scripts/lib/tenant-ownership-fixture.cjs');
const schema = 'authority_checkpoints_' + randomUUID().replaceAll('-', '');
const issuer = 'https://authority-checkpoints.test';
const migrations = path.join(__dirname, '../../migrations');
const administration = new Pool({ connectionString: process.env.IDENTITY_TEST_DATABASE_URL, max: 1 });
let pool; let database; let afterCheckpoint; let checks;
const revalidate = async (user, authorization) => { checks.push([user.jti, authorization]); };
before(async () => {
  await administration.query('CREATE SCHEMA ' + schema); pool = new Pool({ connectionString: process.env.IDENTITY_TEST_DATABASE_URL, max: 8, options: `-c search_path=${schema},public` });
  database = { query: (...args) => pool.query(...args), getClient: () => pool.connect(), transaction: async (operation, options = {}) => {
    const client = await pool.connect();
    try {
      await client.query('BEGIN'); await client.query("SET LOCAL lock_timeout='3s';SET LOCAL statement_timeout='15s'");
      if (options.actor) await client.query("SELECT set_config('opendirectory.actor',$1,true)", [options.actor]);
      const result = await operation(client); if (afterCheckpoint) await afterCheckpoint(client); await client.query('COMMIT'); return result;
    } catch (error) { await client.query('ROLLBACK'); throw error; } finally { client.release(); }
  } };
  for (const file of fs.readdirSync(migrations).filter(file => file.endsWith('.sql')).sort()) await pool.query(fs.readFileSync(path.join(migrations, file), 'utf8'));
});
beforeEach(async () => { afterCheckpoint = null; checks = []; await pool.query('TRUNCATE identity_tenants,users,groups,ous,identity_role_assignments,identity_pim_eligibilities,identity_role_review_policies,identity_role_review_audit CASCADE'); });
after(async () => { afterCheckpoint = null; await pool.end(); await administration.query('DROP SCHEMA ' + schema + ' CASCADE'); await administration.end(); });
async function person(role = 'user', tenant) {
  tenant = tenant || await provisionTenant(database, schema, { enabled: true }); const id = randomUUID(); const subject = 'checkpoint-' + randomUUID();
  await pool.query('INSERT INTO users(id,username,email) VALUES($1,$2,$3)', [id, subject, subject + '@test.invalid']); await pool.query('INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES($1,$2,$3)', [issuer, subject, id]);
  await adoptTenant(database, schema, tenant, [{ kind: 'user', resourceId: id }]); await bootstrapRole(database, { userId: id, role, duration: 3600, reason: 'Explicit finite isolated checkpoint fixture role' });
  const state = await new AuthorizationState(database).state(issuer, subject); const authTime = Math.floor(Date.now() / 1000);
  return { id, tenant, user: { iss: issuer, sub: subject, actor_type: 'user', roles: state.roles, jti: randomUUID(), exp: authTime + 300, identity_authorization: state.context,
    auth_time: authTime, amr: ['pwd', 'otp'], mfa_authorization: { schemaVersion: 1, userId: id, revision: '1', authTime, methods: ['pwd', 'otp'] } } };
}
async function fixture(role = 'role-administrator') { const actor = await person(role); const recipient = await person('user', actor.tenant); return { actor, recipient, roles: new DirectoryRoles(database, { revalidate }) }; }
const grant = fixture => fixture.roles.grant(fixture.recipient.id, { role: 'license-manager', durationSeconds: 300, reason: 'Actual role effect must retain a final SQL command checkpoint' }, fixture.actor.user, 'Bearer original-checkpoint-token');
async function counts() { return (await pool.query(`SELECT (SELECT count(*)::int FROM identity_authority_command_checkpoints) AS checkpoints,(SELECT count(*)::int FROM identity_authority_command_checkpoint_events) AS events,(SELECT count(*)::int FROM identity_authority_command_checkpoint_outbox) AS outbox,
  (SELECT count(*)::int FROM identity_role_assignments) AS assignments,(SELECT count(*)::int FROM identity_role_audit) AS audit`)).rows[0]; }

test('actual role effects commit only with an immutable original-actor checkpoint and matching pending evidence', async () => {
  const current = await fixture(); const result = await grant(current); const row = (await pool.query('SELECT * FROM identity_authority_command_checkpoints')).rows[0];
  assert.equal(result.userId, current.recipient.id); assert.equal(row.user_id, current.actor.id); assert.equal(row.tenant_id, current.actor.tenant); assert.deepEqual(row.original_context, current.actor.user.identity_authorization);
  assert.equal(row.valid_until.getTime(), current.actor.user.exp * 1000); assert.notEqual(row.token_sha256, current.actor.user.jti); assert.match(row.token_sha256, /^[a-f0-9]{64}$/);
  const evidence = (await pool.query('SELECT event.actor,event.details,outbox.status FROM identity_authority_command_checkpoint_events event JOIN identity_authority_command_checkpoint_outbox outbox USING(id)')).rows[0];
  assert.equal(evidence.actor.userId, current.actor.id); assert.equal(evidence.details.kind, 'final-application-checkpoint'); assert.equal(evidence.status, 'pending'); assert.equal(JSON.stringify(evidence).includes('Bearer'), false);
  assert.deepEqual(checks, [[current.actor.user.jti, 'Bearer original-checkpoint-token'], [current.actor.user.jti, 'Bearer original-checkpoint-token']]);
});
test('physical original token expiry after all SQL effects and the final issuer check rolls back the entire command', async () => {
  const current = await fixture(); const before = await counts(); current.actor.user.exp = Math.floor(Date.now() / 1000) + 3; afterCheckpoint = client => client.query('SELECT pg_sleep(3.1)');
  await assert.rejects(grant(current), error => error.status === 401 && error.code === '28000'); assert.equal(checks.length, 2); assert.deepEqual(await counts(), before);
});
test('the original mandatory role-MFA deadline remains physical after the final asynchronous checkpoint', async () => {
  const current = await fixture('authentication-policy-administrator'); const authTime = Math.floor(Date.now() / 1000) - 298; current.actor.user.auth_time = authTime; current.actor.user.mfa_authorization.authTime = authTime;
  const roles = new RoleAuthentication(database, { revalidate }); const policy = await roles.get('license-reader', current.actor.user); const before = await counts(); afterCheckpoint = client => client.query('SELECT pg_sleep(2.1)');
  await assert.rejects(roles.change('license-reader', policyEtag(policy.role, policy.version), { required: true, maxAgeSeconds: 300, reason: 'Role MFA must not expire after returning from the issuer' }, current.actor.user, 'Bearer original-policy-token'), error => error.status === 401 && error.code === '28000');
  afterCheckpoint = null; assert.equal((await roles.get('license-reader', current.actor.user)).version, policy.version); assert.deepEqual(await counts(), before);
});
test('activation-policy writes retain their fixed MFA cutoff through the same SQL commit checkpoint', async () => {
  const current = await fixture('privileged-access-policy-administrator'); const authTime = Math.floor(Date.now() / 1000) - 298; current.actor.user.auth_time = authTime; current.actor.user.mfa_authorization.authTime = authTime;
  const policies = new PrivilegedAccessPolicy(database, { revalidate }); const policy = await policies.get('license-manager', current.actor.user); const before = await counts(); afterCheckpoint = client => client.query('SELECT pg_sleep(2.1)');
  await assert.rejects(policies.change('license-manager', activationEtag(policy.role, policy.version), { required: false, maxDurationSeconds: 60, acknowledgeInvalidation: true, reason: 'Mandatory fresh PIM policy assurance must remain valid through commit' }, current.actor.user, 'Bearer original-policy-token'), error => error.status === 401 && error.code === '28000');
  afterCheckpoint = null; assert.equal((await policies.get('license-manager', current.actor.user)).version, policy.version); assert.deepEqual(await counts(), before);
});
test('review-policy configuration cannot commit after its fixed original MFA deadline', async () => {
  const current = await fixture('access-review-administrator'); const reviewer = await person('access-reviewer', current.actor.tenant); const authTime = Math.floor(Date.now() / 1000) - 298;
  current.actor.user.auth_time = authTime; current.actor.user.mfa_authorization.authTime = authTime; const before = await counts(); afterCheckpoint = client => client.query('SELECT pg_sleep(2.1)');
  await assert.rejects(new RoleReviews(database, { revalidate }).create({ role: 'license-manager', intervalSeconds: 3600, windowSeconds: 300, reviewerUserIds: [reviewer.id], reason: 'Mandatory fresh review policy assurance must remain valid through commit', acknowledgeDeadlines: true }, current.actor.user, 'Bearer original-review-token'), error => error.status === 401 && error.code === '28000');
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_role_review_policies')).rows[0].count, 0); assert.deepEqual(await counts(), before);
});
test('canonical identity, group and policy writes cannot ride a transaction after its final checkpoint even if its GUC is cleared', async () => {
  const current = await fixture(); const foreign = await person(); const before = await counts();
  for (const sql of ["UPDATE users SET title='Unrequested late effect' WHERE id=$1", "INSERT INTO groups(id,name) VALUES($1,'Unrequested late group')", "UPDATE identity_role_authentication SET version=version+1 WHERE role='license-reader'"]) {
    afterCheckpoint = async client => { await client.query("SELECT set_config('opendirectory.authority_command_checkpoint','',true)"); await client.query(sql, sql.includes('$1') ? [foreign.id] : []); };
    await assert.rejects(grant(current), error => error.code === '42501'); assert.deepEqual(await counts(), before);
  }
});
test('clearing checkpoint scope without an extra write still fails deferred receiving', async () => {
  const current = await fixture(); const before = await counts(); afterCheckpoint = client => client.query("SELECT set_config('opendirectory.authority_command_checkpoint','',true)");
  await assert.rejects(grant(current), error => error.code === '42501'); assert.deepEqual(await counts(), before);
});
test('canonical TRUNCATE cannot bypass the post-checkpoint no-effects boundary', async () => {
  const current = await fixture(); const before = await counts(); afterCheckpoint = async client => { await client.query("SELECT set_config('opendirectory.authority_command_checkpoint','',true)"); await client.query('TRUNCATE group_members'); };
  await assert.rejects(grant(current), error => error.code === '42501'); assert.deepEqual(await counts(), before);
});
test('missing exact root, evidence, deferred or canonical no-effects guards deny before command mutation', async () => {
  const current = await fixture(); const before = await counts();
  for (const [table, trigger] of [['identity_authority_command_checkpoints', 'identity_authority_checkpoint_guard'], ['identity_authority_command_checkpoint_events', 'identity_authority_checkpoint_guard'], ['identity_authority_command_checkpoints', 'identity_authority_checkpoint_commit'], ['users', 'aaa_identity_authority_checkpoint_no_effects'], ['groups', 'aaa_identity_authority_checkpoint_no_truncate']]) {
    await pool.query('ALTER TABLE ' + table + ' DISABLE TRIGGER ' + trigger);
    try { await assert.rejects(grant(current), error => error.code === '42501'); } finally { await pool.query('ALTER TABLE ' + table + ' ENABLE TRIGGER ' + trigger); }
  }
  assert.deepEqual(await counts(), before);
});
test('a lost mandatory pending outbox cannot acknowledge a successful authority command', async () => {
  const current = await fixture(); const before = await counts();
  await pool.query('CREATE FUNCTION omit_checkpoint_outbox() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL;END;$$;CREATE TRIGGER zzz_omit_checkpoint_outbox BEFORE INSERT ON identity_authority_command_checkpoint_outbox FOR EACH ROW EXECUTE FUNCTION omit_checkpoint_outbox()');
  try { await assert.rejects(grant(current), error => error.status === 503 && error.code === 'command_checkpoint_receipt_unavailable'); }
  finally { await pool.query('DROP TRIGGER zzz_omit_checkpoint_outbox ON identity_authority_command_checkpoint_outbox;DROP FUNCTION omit_checkpoint_outbox()'); }
  assert.deepEqual(await counts(), before);
});
test('a late trigger cannot replace checkpoint evidence after row admission', async () => {
  const current = await fixture(); const before = await counts();
  await pool.query("CREATE FUNCTION alter_checkpoint_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN NEW.actor='{}';RETURN NEW;END;$$;CREATE TRIGGER zzz_alter_checkpoint_event BEFORE INSERT ON identity_authority_command_checkpoint_events FOR EACH ROW EXECUTE FUNCTION alter_checkpoint_event()");
  try { await assert.rejects(grant(current), error => error.code === '42501'); }
  finally { await pool.query('DROP TRIGGER zzz_alter_checkpoint_event ON identity_authority_command_checkpoint_events;DROP FUNCTION alter_checkpoint_event()'); }
  assert.deepEqual(await counts(), before);
});
test('scope replacement cannot extend the original recorded token deadline or fabricate another final root', async () => {
  const current = await fixture(); const before = await counts(); afterCheckpoint = async client => {
    const scope = (await client.query("SELECT current_setting('opendirectory.authority_command_checkpoint') AS scope")).rows[0].scope; const replaced = JSON.parse(scope); replaced.valid_until = new Date(Date.now() + 86400000).toISOString();
    await client.query("SELECT set_config('opendirectory.authority_command_checkpoint',$1,true)", [JSON.stringify(replaced)]);
  };
  await assert.rejects(grant(current), error => error.code === '42501'); assert.deepEqual(await counts(), before);
});
test('committed checkpoint evidence cannot be rewritten through ordinary owner DML', async () => {
  const current = await fixture(); await grant(current);
  for (const sql of ['DELETE FROM identity_authority_command_checkpoints', "UPDATE identity_authority_command_checkpoint_events SET actor='{}'", "UPDATE identity_authority_command_checkpoint_outbox SET status='sent'"])
    await assert.rejects(pool.query(sql), error => error.code === '42501');
});
test('migration replay preserves every original checkpoint and does not activate an owned authority namespace', async () => {
  const current = await fixture(); await grant(current); const before = (await pool.query('SELECT * FROM identity_authority_command_checkpoints')).rows;
  await pool.query(fs.readFileSync(path.join(migrations, '035_authority_command_checkpoints.sql'), 'utf8')); assert.deepEqual((await pool.query('SELECT * FROM identity_authority_command_checkpoints')).rows, before);
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_authority_namespaces')).rows[0].count, 0); assert.equal((await new AuthorizationState(database).state(issuer, current.actor.user.sub)).schemaVersion, 6);
});
test('SQL-only checkpoint definers do not let a real limited login or assumed role impersonate the receiving owner', async () => {
  const current = await fixture(); const role = 'limited_checkpoint_' + randomUUID().replaceAll('-', ''); let limited;
  await administration.query(`CREATE ROLE ${role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS`);
  try {
    await pool.query(`GRANT USAGE ON SCHEMA ${schema} TO ${role};GRANT EXECUTE ON FUNCTION identity_authority_command_context(jsonb),identity_authority_command_checkpoint(uuid,jsonb,jsonb,bigint) TO ${role}`);
    const address = new URL(process.env.IDENTITY_TEST_DATABASE_URL); address.username = role; limited = new Pool({ connectionString: address.toString(), max: 1, options: `-c search_path=${schema},public` });
    const proof = { ...current.actor.user.identity_authorization, issuer, subject: current.actor.user.sub };
    await assert.rejects(limited.query('SELECT identity_authority_command_context($1)', [proof]), error => error.code === '42501');
    const client = await pool.connect(); try { await client.query('BEGIN'); await client.query('SET LOCAL ROLE ' + role); await assert.rejects(client.query('SELECT identity_authority_command_context($1)', [proof]), error => error.code === '42501'); }
    finally { await client.query('ROLLBACK'); client.release(); }
  } finally { await limited?.end(); await pool.query('DROP OWNED BY ' + role); await administration.query('DROP ROLE ' + role); }
});
test('actual session time zones cannot alter checkpoint content hashes and large context revisions stay strings', async () => {
  const current = await fixture(); await pool.query("SELECT setval('identity_authorization_revision_seq',9007199254740992,true)"); await pool.query('UPDATE users SET authorization_revision=authorization_revision+1 WHERE id=$1', [current.actor.id]); current.actor.user.identity_authorization = (await new AuthorizationState(database).state(issuer, current.actor.user.sub)).context;
  const original = database.transaction; database.transaction = (operation, options) => original(async client => { await client.query("SET LOCAL timezone='Pacific/Honolulu'"); return operation(client); }, options);
  try { await grant(current); } finally { database.transaction = original; }
  const row = (await pool.query('SELECT original_context FROM identity_authority_command_checkpoints')).rows[0]; assert.equal(row.original_context.revision, '9007199254740993');
});
test('actual role expiry after the final checkpoint invalidates its local source snapshot without a revocation worker', async () => {
  const current = await fixture('user'); const administrator = await person('admin', current.actor.tenant);
  await database.transaction(client => client.query("INSERT INTO identity_role_assignments(user_id,role,reason,expires_at) VALUES($1,'role-administrator','Actual short original role source for deferred snapshot expiry',clock_timestamp()+interval '3 seconds')", [current.actor.id]), { actor: JSON.stringify({ issuer, subject: administrator.user.sub, userId: administrator.id }) });
  const state = await new AuthorizationState(database).state(issuer, current.actor.user.sub); current.actor.user.roles = state.roles; current.actor.user.identity_authorization = state.context;
  const before = await counts(); afterCheckpoint = client => client.query('SELECT pg_sleep(3.1)'); await assert.rejects(grant(current), error => error.code === '42501'); assert.deepEqual(await counts(), before);
});
