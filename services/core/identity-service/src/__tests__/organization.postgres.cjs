'use strict';

const { test, before, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { Pool } = require('pg');
const { OrganizationProfile } = require('../OrganizationProfile');
const { OrganizationDelegations } = require('../OrganizationDelegations');
const { getIdentityPermissions } = require('../middleware/identityAccess');
const { AuthorizationState } = require('../AuthorizationState');
const { bootstrapRole } = require('../../scripts/bootstrap-role');
const { provisionTenant, adoptTenant, enableTenant } = require('../../../../../scripts/lib/tenant-ownership-fixture.cjs');
const schema = 'organization_' + randomUUID().replaceAll('-', '');
const issuer = 'https://organization.test';
const migrations = path.join(__dirname, '../../migrations');
const administration = new Pool({ connectionString: process.env.IDENTITY_TEST_DATABASE_URL, max: 1 });
const profile = { name: 'Actual Company AG', legalForm: 'AG', registrationNumber: 'Register 123', taxId: 'UID 123', addressLine1: 'Beispielstrasse 1', addressLine2: '', postalCode: '8000', city: 'Zürich', country: 'CH', timezone: 'Europe/Zurich', defaultLanguage: 'de', contactEmail: 'office@example.invalid', contactPhone: '+41 44 123 45 67', website: 'https://example.invalid' };
const body = { profile, reason: 'Actual reviewed organization profile change' };
let pool; let database; let store; let checks; let afterCheckpoint; let rejectFinal;
before(async () => {
  await administration.query('CREATE SCHEMA ' + schema); pool = new Pool({ connectionString: process.env.IDENTITY_TEST_DATABASE_URL, max: 8, options: `-c search_path=${schema},public` });
  database = { query: (...args) => pool.query(...args), getClient: () => pool.connect(), transaction: async (operation, options = {}) => {
    const client = await pool.connect();
    try {
      await client.query(options.readOnly ? 'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY' : 'BEGIN'); await client.query("SET LOCAL lock_timeout='3s';SET LOCAL statement_timeout='15s'");
      if (options.actor) await client.query("SELECT set_config('opendirectory.actor',$1,true)", [options.actor]);
      const result = await operation(client); if (!options.readOnly && afterCheckpoint) await afterCheckpoint(client); await client.query('COMMIT'); return result;
    } catch (error) { await client.query('ROLLBACK'); throw error; } finally { client.release(); }
  } };
  for (const file of fs.readdirSync(migrations).filter(file => file.endsWith('.sql')).sort()) await pool.query(fs.readFileSync(path.join(migrations, file), 'utf8'));
  store = new OrganizationProfile(database, { revalidate: async (user, authorization) => { checks.push([user.jti, authorization]); if (rejectFinal && checks.length === 2) throw Object.assign(new Error('withdrawn_original_bearer'), { status: 401 }); } });
});
beforeEach(async () => { checks = []; afterCheckpoint = null; rejectFinal = false; await pool.query('TRUNCATE identity_tenants,users,groups,ous,identity_role_assignments,identity_pim_eligibilities,identity_role_review_policies CASCADE'); });
after(async () => { afterCheckpoint = null; await pool.end(); await administration.query('DROP SCHEMA ' + schema + ' CASCADE'); await administration.end(); });
async function person(role = 'admin', tenant) {
  tenant = tenant || await provisionTenant(database, schema, { enabled: true }); const id = randomUUID(); const subject = 'organization-' + id;
  await pool.query('INSERT INTO users(id,username,email) VALUES($1,$2,$3)', [id, subject, subject + '@test.invalid']); await pool.query('INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES($1,$2,$3)', [issuer, subject, id]);
  await adoptTenant(database, schema, tenant, [{ kind: 'user', resourceId: id }]); await bootstrapRole(database, { userId: id, role, duration: 3600, reason: 'Explicit finite organization management fixture authority' });
  const state = await new AuthorizationState(database).state(issuer, subject); const authTime = Math.floor(Date.now() / 1000);
  return { id, tenant, user: { iss: issuer, sub: subject, actor_type: 'user', roles: state.roles, identity_authorization: state.context, jti: randomUUID(), exp: authTime + 300,
    auth_time: authTime, amr: ['pwd', 'otp'], mfa_authorization: { schemaVersion: 1, userId: id, revision: '1', authTime, methods: ['pwd', 'otp'] } } };
}
const save = (actor, page, change = body) => store.save(change, page.etag, actor.user, 'Bearer original-organization-token');
async function counts() { return (await pool.query('SELECT (SELECT count(*)::int FROM identity_organization_profiles) AS profiles,(SELECT count(*)::int FROM identity_organization_events) AS events,(SELECT count(*)::int FROM identity_organization_outbox) AS outbox,(SELECT count(*)::int FROM identity_authority_command_checkpoints) AS checkpoints')).rows[0]; }

test('the actual own-company profile creates and updates with versions, original actor, immutable audit, pending outbox and final checkpoint', async () => {
  const actor = await person(); const empty = await store.get(actor.user); assert.equal(empty.organization, null); assert.equal(empty.verificationSupported, false); assert.equal(empty.canManage, true);
  const created = await save(actor, empty); assert.equal(created.organization.version, '1'); assert.equal(created.tenant.id, actor.tenant); assert.equal(created.actorUserId, actor.id); assert.equal(created.organization.name, profile.name);
  const updated = await save(actor, created, { ...body, profile: { ...profile, city: 'Bern' } }); assert.equal(updated.organization.version, '2'); assert.equal(updated.organization.id, created.organization.id); assert.equal(updated.organization.city, 'Bern'); assert.equal(updated.tenant.version, empty.tenant.version);
  assert.deepEqual(await counts(), { profiles: 1, events: 2, outbox: 2, checkpoints: 2 });
  const events = (await pool.query('SELECT * FROM identity_organization_events ORDER BY created_at')).rows; assert.equal(events[0].before_state, null); assert.equal(events[1].before_state.city, 'Zürich'); assert.equal(events[1].after_state.city, 'Bern'); assert.equal(events[1].actor.userId, actor.id); assert.equal(JSON.stringify(events).includes('Bearer'), false);
  assert.deepEqual(checks, [[actor.user.jti, 'Bearer original-organization-token'], [actor.user.jti, 'Bearer original-organization-token'], [actor.user.jti, 'Bearer original-organization-token'], [actor.user.jti, 'Bearer original-organization-token']]);
});
test('two real tenants cannot target each other even with global administration and a known foreign ETag', async () => {
  const own = await person(); const foreign = await person(); const ownPage = await store.get(own.user); const foreignPage = await save(foreign, await store.get(foreign.user), { ...body, profile: { ...profile, name: 'Foreign Company' } });
  await assert.rejects(save(own, foreignPage), error => error.status === 412); assert.equal((await store.get(own.user)).organization, null); assert.equal((await store.get(foreign.user)).organization.name, 'Foreign Company');
  const created = await save(own, ownPage); assert.equal(created.tenant.id, own.tenant); assert.equal(await pool.query('SELECT count(*)::int AS count FROM identity_organization_profiles').then(result => result.rows[0].count), 2);
});
test('foreign held users are not locked while saving the owned organization', async () => {
  const actor = await person(); const foreign = await person(); const page = await store.get(actor.user); const blocker = await pool.connect();
  try { await blocker.query('BEGIN'); await blocker.query('SELECT id FROM users WHERE id=$1 FOR UPDATE', [foreign.id]); const start = Date.now(); await save(actor, page); assert.ok(Date.now() - start < 2000); }
  finally { await blocker.query('ROLLBACK'); blocker.release(); }
});
test('non-administrators and workloads cannot read or mutate the profile', async () => {
  const actor = await person('license-manager'); await assert.rejects(store.get(actor.user), error => error.status === 403); await assert.rejects(save(actor, { etag: 'invented' }), error => error.status === 403);
  await assert.rejects(store.get({ ...actor.user, actor_type: 'application' }), error => error.status === 403); assert.equal((await counts()).profiles, 0);
});
test('stale MFA permits the authorized read but not mutation and stale/missing versions never overwrite', async () => {
  const actor = await person(); actor.user.auth_time -= 301; actor.user.mfa_authorization.authTime -= 301;
  const page = await store.get(actor.user); assert.equal(page.requiresFreshMfa, true); assert.equal(page.canManage, false); await assert.rejects(save(actor, page), error => error.status === 428);
  actor.user.auth_time += 301; actor.user.mfa_authorization.authTime += 301; await assert.rejects(store.save(body, '', actor.user, 'Bearer original'), error => error.status === 428);
  await save(actor, page); await assert.rejects(save(actor, page), error => error.status === 412); assert.equal((await store.get(actor.user)).organization.version, '1');
});
test('tenant selectors, unknown fields, invalid contacts, unsafe URLs and unsupported time zones fail without mutation', async () => {
  const actor = await person(); const page = await store.get(actor.user);
  for (const change of [{ ...body, tenantId: randomUUID() }, { ...body, profile: { ...profile, tenantId: randomUUID() } }, ...[{ contactEmail: 'bad' }, { website: 'javascript:alert(1)' }, { timezone: 'Invented/Zone' }, { name: 'x' }, { country: 'not-a-country' }].map(fields => ({ ...body, profile: { ...profile, ...fields } }))]) await assert.rejects(save(actor, page, change), error => error.status === 400);
  assert.equal((await counts()).profiles, 0);
});
test('withdrawing the original bearer after DML rolls the profile and all evidence back', async () => {
  const actor = await person(); const page = await store.get(actor.user); rejectFinal = true;
  await assert.rejects(save(actor, page), error => error.status === 401); assert.deepEqual(await counts(), { profiles: 0, events: 0, outbox: 0, checkpoints: 0 });
});
test('real original-MFA expiry after the final application check rolls everything back at SQL commit', async () => {
  const actor = await person(); const page = await store.get(actor.user); actor.user.auth_time -= 298; actor.user.mfa_authorization.authTime -= 298; afterCheckpoint = client => client.query('SELECT pg_sleep(2.1)');
  await assert.rejects(save(actor, page), error => error.status === 401); assert.equal(checks.length, 2); assert.deepEqual(await counts(), { profiles: 0, events: 0, outbox: 0, checkpoints: 0 });
});
test('missing profile/event/outbox/deferred or no-effects guards are unavailable before any partial write', async () => {
  const actor = await person(); const page = await store.get(actor.user);
  for (const [table, trigger] of [['identity_organization_profiles', 'identity_organization_guard'], ['identity_organization_events', 'identity_organization_guard'], ['identity_organization_outbox', 'identity_organization_guard'], ['identity_organization_profiles', 'identity_organization_commit'], ['users', 'aaa_identity_organization_no_effects'], ['groups', 'aaa_identity_organization_no_truncate']]) {
    await pool.query('ALTER TABLE ' + table + ' DISABLE TRIGGER ' + trigger); try { await assert.rejects(save(actor, page), error => error.status === 503); } finally { await pool.query('ALTER TABLE ' + table + ' ENABLE TRIGGER ' + trigger); }
  }
  assert.equal((await counts()).profiles, 0);
});
test('an omitted outbox and a late profile rewrite cannot produce a successful response', async () => {
  const actor = await person(); const page = await store.get(actor.user);
  for (const [table, statement] of [['identity_organization_outbox', 'RETURN NULL;'], ['identity_organization_profiles', "NEW.city='Unrequested City';RETURN NEW;"]]) {
    await pool.query('CREATE FUNCTION alter_organization_effect() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN ' + statement + 'END;$$;CREATE TRIGGER zzz_alter_organization_effect BEFORE INSERT ON ' + table + ' FOR EACH ROW EXECUTE FUNCTION alter_organization_effect()');
    try { await assert.rejects(save(actor, page), error => error.status === 503); } finally { await pool.query('DROP TRIGGER zzz_alter_organization_effect ON ' + table + ';DROP FUNCTION alter_organization_effect()'); }
  }
  assert.equal((await counts()).profiles, 0);
});
test('clearing mutation scope cannot hide unrelated writes or an absent final admission', async () => {
  const actor = await person(); const page = await store.get(actor.user);
  for (const effect of [async () => {}, client => client.query("UPDATE users SET title='unrequested' WHERE id=$1", [actor.id]), client => client.query('TRUNCATE group_members')]) {
    afterCheckpoint = async client => { await client.query("SELECT set_config('opendirectory.organization_mutation','',true),set_config('opendirectory.authority_command_checkpoint','',true)"); await effect(client); };
    await assert.rejects(save(actor, page), error => error.status === 503); assert.equal((await counts()).profiles, 0);
  }
});
test('disabled or rebound actors cannot use a retained valid-looking profile page', async () => {
  const actor = await person(); const page = await store.get(actor.user); await enableTenant(database, schema, actor.tenant, false);
  await assert.rejects(save(actor, page), error => error.status === 401); assert.equal((await counts()).profiles, 0);
});
test('unscoped SQL cannot change profiles or immutable evidence and migration replay preserves real content', async () => {
  const actor = await person(); const created = await save(actor, await store.get(actor.user));
  for (const statement of ["UPDATE identity_organization_profiles SET city='Forged'", 'DELETE FROM identity_organization_profiles', "UPDATE identity_organization_events SET reason='Forged historical reason'", 'DELETE FROM identity_organization_outbox']) await assert.rejects(pool.query(statement), error => error.code === '42501');
  await pool.query(fs.readFileSync(path.join(migrations, '037_organization_profiles.sql'), 'utf8')); assert.deepEqual(await store.get(actor.user), created); assert.equal((await counts()).events, 1);
});
test('actual concurrent organization writes observe a real row-lock wait and only one old-version update commits', { timeout: 15000 }, async () => {
  const actor = await person(); const other = await person('admin', actor.tenant); const created = await save(actor, await store.get(actor.user));
  let signalReady; let release; const ready = new Promise(resolve => { signalReady = resolve; }); const gate = new Promise(resolve => { release = resolve; }); let hold = true;
  afterCheckpoint = async () => { if (hold) { hold = false; signalReady(); await gate; } };
  const first = save(actor, created, { ...body, profile: { ...profile, city: 'First Writer' } }); await ready;
  const second = save(other, created, { ...body, profile: { ...profile, city: 'Second Writer' } }).then(value => ({ value }), error => ({ error }));
  try {
    const until = Date.now() + 2500; let observed = false;
    while (Date.now() < until) { observed = (await pool.query("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'SELECT identity_organization_save%') AS waiting")).rows[0].waiting; if (observed) break; await new Promise(resolve => setTimeout(resolve, 10)); }
    assert.equal(observed, true);
  } finally { release(); }
  assert.equal((await first).organization.city, 'First Writer'); assert.equal((await second).error.status, 412); afterCheckpoint = null;
  assert.equal((await store.get(actor.user)).organization.version, '2'); assert.equal((await counts()).events, 2);
});
test('lost prior pending evidence makes the profile unavailable rather than silently rebasing a later update', async () => {
  const actor = await person(); const created = await save(actor, await store.get(actor.user));
  await pool.query('ALTER TABLE identity_organization_outbox DISABLE TRIGGER identity_organization_guard');
  try { await pool.query('DELETE FROM identity_organization_outbox'); } finally { await pool.query('ALTER TABLE identity_organization_outbox ENABLE TRIGGER identity_organization_guard'); }
  await assert.rejects(store.get(actor.user), error => error.status === 503); await assert.rejects(save(actor, created), error => error.status === 503); assert.equal((await counts()).events, 1);
});
test('a granted definer cannot turn a real limited login or SET ROLE into organization-write authority', async () => {
  const actor = await person(); const recipient = await person('user', actor.tenant); const page = await store.get(actor.user); const role = 'organization_limited_' + randomUUID().replaceAll('-', ''); let limited;
  await administration.query('CREATE ROLE ' + role + ' LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS');
  try {
    await pool.query('GRANT USAGE ON SCHEMA ' + schema + ' TO ' + role + ';GRANT EXECUTE ON FUNCTION identity_organization_save(jsonb,text,text,jsonb,text,bigint),identity_organization_delegation_change(jsonb,text,text,uuid,integer,text,bigint) TO ' + role);
    const address = new URL(process.env.IDENTITY_TEST_DATABASE_URL); address.username = role; limited = new Pool({ connectionString: address.toString(), max: 1, options: `-c search_path=${schema},public` });
    for (const command of ['profile', 'delegation']) for (const assumed of [false, true]) {
      const client = await (assumed ? pool : limited).connect();
      try { await client.query('BEGIN'); if (assumed) await client.query('SET LOCAL ROLE ' + role);
        const proof = JSON.stringify({ ...actor.user.identity_authorization, issuer, subject: actor.user.sub });
        const attempted = command === 'profile'
          ? client.query('SELECT identity_organization_save($1::jsonb,$2,$3,$4::jsonb,$5,$6::bigint)', [proof, actor.user.jti, page.etag, JSON.stringify(profile), body.reason, actor.user.exp])
          : client.query('SELECT identity_organization_delegation_change($1::jsonb,$2,$3,$4::uuid,$5::int,$6,$7::bigint)', [proof, actor.user.jti, 'granted', recipient.id, 300, body.reason, actor.user.exp]);
        await assert.rejects(attempted, error => error.code === '42501' && error.message.includes('Actual database owner required'));
      } finally { await client.query('ROLLBACK'); client.release(); }
    }
  } finally { await limited?.end(); await pool.query('DROP OWNED BY ' + role); await administration.query('DROP ROLE ' + role); }
  assert.equal((await counts()).profiles, 0);
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_organization_delegations')).rows[0].count, 0);
});
test('actual above-safe-integer tenant generations and caller time zones preserve exact ETags and retained receipts', async () => {
  await pool.query("SELECT setval('identity_tenant_generation_seq',9007199254740993,true)"); const actor = await person(); const initial = await store.get(actor.user);
  assert.ok(BigInt(initial.tenant.generation) > BigInt(Number.MAX_SAFE_INTEGER)); const created = await save(actor, initial);
  await pool.query("SET timezone='Pacific/Honolulu'"); assert.deepEqual(await store.get(actor.user), created); assert.ok(created.etag.includes(initial.tenant.generation));
});

function delegationStore() { return new OrganizationDelegations(database, { revalidate: store.commands.revalidate }); }
const delegationReason = 'Actual independently reviewed own-company profile delegation';
const grantTo = (administrator, recipient) => delegationStore().change('granted', recipient.id, { userId: recipient.id, durationSeconds: 3600, reason: delegationReason }, administrator.user, 'Bearer original-organization-token');
async function refreshPerson(actor) { const state = await new AuthorizationState(database).state(issuer, actor.user.sub); actor.user.identity_authorization = state.context; actor.user.roles = state.roles; return actor; }
test('a real own-company delegation permits profile editing without any global administrator or role-management authority', async () => {
  const administrator = await person(); const recipient = await person('user', administrator.tenant); const oldRevision = recipient.user.identity_authorization.revision;
  const confirmed = await grantTo(administrator, recipient); await refreshPerson(recipient);
  assert.notEqual(recipient.user.identity_authorization.revision, oldRevision); assert.deepEqual(recipient.user.roles, ['user']); assert.deepEqual(getIdentityPermissions(recipient.user), []);
  assert.deepEqual(await delegationStore().permissions(recipient.user), ['organization.read', 'organization.manage']);
  const saved = await save(recipient, await store.get(recipient.user)); assert.equal(saved.organization.version, '1'); assert.equal(saved.actorUserId, recipient.id);
  await assert.rejects(delegationStore().list(recipient.user), error => error.status === 403);
  await assert.rejects(grantTo(recipient, administrator), error => error.status === 403);
  const rows = (await pool.query('SELECT event.*,outbox.status FROM identity_organization_delegation_events event JOIN identity_organization_delegation_outbox outbox USING(id)')).rows;
  assert.equal(rows.length, 1); assert.equal(rows[0].id, confirmed.eventId); assert.equal(rows[0].actor.userId, administrator.id); assert.equal(rows[0].status, 'pending'); assert.equal(JSON.stringify(rows).includes('Bearer'), false);
  assert.equal((await delegationStore().list(administrator.user)).grants[0].status, 'active');
});
test('delegated reads and writes require fresh real MFA rather than treating an ordinary login as privileged access', async () => {
  const administrator = await person(); const recipient = await person('user', administrator.tenant); await grantTo(administrator, recipient); await refreshPerson(recipient);
  const fresh = await store.get(recipient.user);
  recipient.user.auth_time -= 301; recipient.user.mfa_authorization.authTime -= 301;
  await assert.rejects(store.get(recipient.user), error => error.status === 428); await assert.rejects(save(recipient, fresh), error => error.status === 428);
  assert.equal((await counts()).profiles, 0);
});
test('delegation rejects foreign, unknown, inactive and self targets without changing a user or creating authority', async () => {
  const administrator = await person(); const foreign = await person('user'); const inactive = await person('user', administrator.tenant); await pool.query('UPDATE users SET enabled=false WHERE id=$1', [inactive.id]);
  for (const target of [foreign, inactive, { id: randomUUID() }]) await assert.rejects(grantTo(administrator, target), error => error.status === 404);
  await assert.rejects(grantTo(administrator, administrator), error => error.status === 400);
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_organization_delegations')).rows[0].count, 0);
});
test('revocation retains exact evidence, invalidates the old subject context and removes only the delegated profile permission', async () => {
  const administrator = await person(); const recipient = await person('user', administrator.tenant); const confirmed = await grantTo(administrator, recipient); await refreshPerson(recipient); const captured = structuredClone(recipient.user);
  const revoked = await delegationStore().change('revoked', confirmed.grantId, { reason: delegationReason }, administrator.user, 'Bearer original-organization-token');
  assert.equal(revoked.action, 'revoked'); await assert.rejects(store.get(captured), error => error.status === 401); await refreshPerson(recipient);
  assert.deepEqual(await delegationStore().permissions(recipient.user), []); await assert.rejects(store.get(recipient.user), error => error.status === 403); assert.deepEqual(recipient.user.roles, ['user']);
  assert.equal((await delegationStore().list(administrator.user)).grants[0].status, 'revoked');
  await assert.rejects(delegationStore().change('revoked', confirmed.grantId, { reason: delegationReason }, administrator.user, 'Bearer original-organization-token'), error => error.status === 409);
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_organization_delegation_events')).rows[0].count, 2);
});
test('a real concurrent second grant waits on the same owned user and cannot create duplicate active authority', { timeout: 15000 }, async () => {
  const administrator = await person(); const other = await person('admin', administrator.tenant); const recipient = await person('user', administrator.tenant);
  let readySignal; let release; const ready = new Promise(resolve => { readySignal = resolve; }); const gate = new Promise(resolve => { release = resolve; }); let hold = true;
  afterCheckpoint = async () => { if (hold) { hold = false; readySignal(); await gate; } };
  const first = grantTo(administrator, recipient); await ready; const second = grantTo(other, recipient).then(value => ({ value }), error => ({ error }));
  try { const until = Date.now() + 2000; let waiting = false;
    while (Date.now() < until) { waiting = (await pool.query("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'SELECT identity_organization_delegation_change%') AS waiting")).rows[0].waiting; if (waiting) break; await new Promise(resolve => setTimeout(resolve, 10)); }
    assert.equal(waiting, true);
  } finally { release(); }
  await first; assert.equal((await second).error.status, 409); afterCheckpoint = null;
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_organization_delegations')).rows[0].count, 1);
});
test('missing delegation receiving guards prevent positive permissions and new management writes', async () => {
  const administrator = await person(); const recipient = await person('user', administrator.tenant); const other = await person('user', administrator.tenant); await grantTo(administrator, recipient); await refreshPerson(recipient);
  await pool.query('ALTER TABLE identity_organization_delegation_outbox DISABLE TRIGGER identity_organization_delegation_guard');
  try { await assert.rejects(delegationStore().permissions(recipient.user), error => error.status === 503); await assert.rejects(delegationStore().list(administrator.user), error => error.status === 503); await assert.rejects(grantTo(administrator, other), error => error.status === 503); }
  finally { await pool.query('ALTER TABLE identity_organization_delegation_outbox ENABLE TRIGGER identity_organization_delegation_guard'); }
});
test('lost pending delegation evidence cannot silently become a positive profile permission', async () => {
  const administrator = await person(); const recipient = await person('user', administrator.tenant); await grantTo(administrator, recipient); await refreshPerson(recipient);
  await pool.query('ALTER TABLE identity_organization_delegation_outbox DISABLE TRIGGER identity_organization_delegation_guard');
  try { await pool.query('DELETE FROM identity_organization_delegation_outbox'); } finally { await pool.query('ALTER TABLE identity_organization_delegation_outbox ENABLE TRIGGER identity_organization_delegation_guard'); }
  await assert.rejects(delegationStore().permissions(recipient.user), error => error.status === 503); await assert.rejects(store.get(recipient.user), error => error.status === 503);
});
test('original issuer withdrawal rolls back delegation, target invalidation and all audit/outbox effects together', async () => {
  const administrator = await person(); const recipient = await person('user', administrator.tenant); const revision = recipient.user.identity_authorization.revision; checks = []; rejectFinal = true;
  await assert.rejects(grantTo(administrator, recipient), error => error.status === 401); rejectFinal = false; await refreshPerson(recipient);
  assert.equal(recipient.user.identity_authorization.revision, revision); assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_organization_delegations')).rows[0].count, 0);
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_organization_delegation_outbox')).rows[0].count, 0);
});
test('delegation evidence is immutable and replaying migration 038 preserves the existing 62-role authority catalog', async () => {
  const administrator = await person(); const recipient = await person('user', administrator.tenant); await grantTo(administrator, recipient);
  const before = await delegationStore().list(administrator.user);
  for (const statement of ['DELETE FROM identity_organization_delegations', 'DELETE FROM identity_organization_delegation_events', 'DELETE FROM identity_organization_delegation_outbox']) await assert.rejects(pool.query(statement), error => error.code === '42501');
  await pool.query(fs.readFileSync(path.join(migrations, '038_organization_delegations.sql'), 'utf8')); assert.deepEqual(await delegationStore().list(administrator.user), before);
  assert.equal((await pool.query("SELECT jsonb_array_length(identity_authority_catalog()->'roles') AS count")).rows[0].count, 62);
});
test('the physical delegation expiry is fenced through the profile commit, not merely at the earlier permission lookup', { timeout: 15000 }, async () => {
  const administrator = await person(); const recipient = await person('user', administrator.tenant); const confirmed = await grantTo(administrator, recipient); await refreshPerson(recipient);
  await pool.query('ALTER TABLE identity_organization_delegations DISABLE TRIGGER identity_organization_delegation_guard;ALTER TABLE identity_organization_delegation_events DISABLE TRIGGER identity_organization_delegation_guard');
  let deadline;
  try {
    deadline = (await pool.query("UPDATE identity_organization_delegations SET expires_at=date_trunc('second',clock_timestamp())+interval '3 seconds' WHERE id=$1 RETURNING expires_at", [confirmed.grantId])).rows[0].expires_at;
    await pool.query('UPDATE identity_organization_delegation_events SET expires_at=$2 WHERE id=$1', [confirmed.grantId, deadline]);
  } finally { await pool.query('ALTER TABLE identity_organization_delegations ENABLE TRIGGER identity_organization_delegation_guard;ALTER TABLE identity_organization_delegation_events ENABLE TRIGGER identity_organization_delegation_guard'); }
  const initial = await store.get(recipient.user); afterCheckpoint = async () => { await new Promise(resolve => setTimeout(resolve, Math.max(0, deadline.getTime() - Date.now()) + 100)); };
  await assert.rejects(save(recipient, initial), error => error.status === 401 || error.code === '28000'); afterCheckpoint = null; assert.equal((await counts()).profiles, 0);
  assert.deepEqual(await delegationStore().permissions(recipient.user), []);
});
test('an actually omitted delegation outbox cannot confirm a grant or leave the target authorization invalidation behind', async () => {
  const administrator = await person(); const recipient = await person('user', administrator.tenant); const before = recipient.user.identity_authorization.revision;
  await pool.query('CREATE FUNCTION organization_test_omit_delegation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$;CREATE TRIGGER zz_omit_delegation BEFORE INSERT ON identity_organization_delegation_outbox FOR EACH ROW EXECUTE FUNCTION organization_test_omit_delegation()');
  try { await assert.rejects(grantTo(administrator, recipient), error => error.status === 503); }
  finally { await pool.query('DROP TRIGGER zz_omit_delegation ON identity_organization_delegation_outbox;DROP FUNCTION organization_test_omit_delegation()'); }
  await refreshPerson(recipient); assert.equal(recipient.user.identity_authorization.revision, before); assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_organization_delegations')).rows[0].count, 0);
});
test('an inactive own user cannot receive new authority but its retained delegation can still be revoked for offboarding', async () => {
  const administrator = await person(); const recipient = await person('user', administrator.tenant); const granted = await grantTo(administrator, recipient);
  await pool.query('UPDATE users SET enabled=false WHERE id=$1', [recipient.id]); assert.equal((await delegationStore().list(administrator.user)).grants[0].status, 'inactive');
  const revoked = await delegationStore().change('revoked', granted.grantId, { reason: delegationReason }, administrator.user, 'Bearer original-organization-token');
  assert.equal(revoked.action, 'revoked'); assert.equal((await delegationStore().list(administrator.user)).grants[0].status, 'revoked');
});
test('actual profile-write and delegation-revocation concurrency is serialized on the original subject rather than allowing a write after committed withdrawal', { timeout: 15000 }, async () => {
  const administrator = await person(); const recipient = await person('user', administrator.tenant); const granted = await grantTo(administrator, recipient); await refreshPerson(recipient); const initial = await store.get(recipient.user);
  let readySignal; let release; const ready = new Promise(resolve => { readySignal = resolve; }); const gate = new Promise(resolve => { release = resolve; }); let hold = true;
  afterCheckpoint = async () => { if (hold) { hold = false; readySignal(); await gate; } };
  const writing = save(recipient, initial); await ready;
  const revoking = delegationStore().change('revoked', granted.grantId, { reason: delegationReason }, administrator.user, 'Bearer original-organization-token');
  try { let waiting = false; const until = Date.now() + 2000;
    while (Date.now() < until) { waiting = (await pool.query("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'SELECT identity_organization_delegation_change%') AS waiting")).rows[0].waiting; if (waiting) break; await new Promise(resolve => setTimeout(resolve, 10)); }
    assert.equal(waiting, true);
  } finally { release(); }
  assert.equal((await writing).organization.version, '1'); await revoking; afterCheckpoint = null;
  await assert.rejects(save(recipient, initial), error => error.status === 401); await refreshPerson(recipient); await assert.rejects(store.get(recipient.user), error => error.status === 403);
});
test('a cleared delegation scope cannot hide unrelated writes after the actual final checkpoint and commit everything anyway', async () => {
  const administrator = await person(); const recipient = await person('user', administrator.tenant); const before = recipient.user.identity_authorization.revision;
  afterCheckpoint = async client => { await client.query("SELECT set_config('opendirectory.organization_delegation','',true),set_config('opendirectory.authority_checkpoint','',true)"); await client.query("UPDATE users SET display_name='Unrelated late write' WHERE id=$1", [recipient.id]); };
  await assert.rejects(grantTo(administrator, recipient), error => error.status === 503 || error.code === '42501'); afterCheckpoint = null;
  await refreshPerson(recipient); assert.equal(recipient.user.identity_authorization.revision, before); assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_organization_delegations')).rows[0].count, 0);
});
