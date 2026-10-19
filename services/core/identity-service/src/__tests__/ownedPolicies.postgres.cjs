'use strict';

const { test, before, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { Pool } = require('pg');
const { ROLES } = require('../../../../../packages/directory-role-contract');
const { AuthorizationState } = require('../AuthorizationState');
const { PrivilegedActivation } = require('../PrivilegedActivation');
const { bootstrapRole } = require('../../scripts/bootstrap-role');
const { provisionTenant, adoptTenant, enableTenant } = require('../../../../../scripts/lib/tenant-ownership-fixture.cjs');

const schema = 'owned_policies_' + randomUUID().replaceAll('-', '');
const issuer = 'https://owned-policies.test';
const migrations = path.join(__dirname, '../../migrations');
const administration = new Pool({ connectionString: process.env.IDENTITY_TEST_DATABASE_URL, max: 1 });
let pool; let database;
before(async () => {
  await administration.query('CREATE SCHEMA ' + schema); pool = new Pool({ connectionString: process.env.IDENTITY_TEST_DATABASE_URL, max: 8, options: `-c search_path=${schema},public` });
  database = { query: (...args) => pool.query(...args), getClient: () => pool.connect(), transaction: async (operation, options = {}) => {
    const client = await pool.connect();
    try {
      await client.query(options.readOnly ? 'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY' : 'BEGIN'); await client.query("SET LOCAL lock_timeout='5s';SET LOCAL statement_timeout='15s'");
      if (options.actor) await client.query("SELECT set_config('opendirectory.actor',$1,true)", [options.actor]);
      const result = await operation(client); await client.query('COMMIT'); return result;
    } catch (error) { await client.query('ROLLBACK'); throw error; } finally { client.release(); }
  } };
  for (const file of fs.readdirSync(migrations).filter(file => file.endsWith('.sql')).sort()) await pool.query(fs.readFileSync(path.join(migrations, file), 'utf8'));
});
beforeEach(async () => {
  await pool.query('TRUNCATE identity_tenants,users,groups,ous,identity_role_review_policies,identity_role_assignments,identity_pim_eligibilities CASCADE');
  await database.transaction(async client => {
    await client.query("SELECT set_config('opendirectory.authentication_reason','Explicit isolated legacy policy fixture reset',true),set_config('opendirectory.activation_reason','Explicit isolated legacy policy fixture reset',true)");
    await client.query("UPDATE identity_role_authentication SET mfa_required=false,max_age_seconds=3600,version=version+1 WHERE role='license-manager' AND (mfa_required OR max_age_seconds<>3600)");
    await client.query("UPDATE identity_role_activation_policies SET activation_required=false,max_duration_seconds=28800,reviewer_user_ids='{}',version=version+1 WHERE role='license-manager' AND (activation_required OR max_duration_seconds<>28800 OR cardinality(reviewer_user_ids)<>0)");
  }, { actor: 'explicit-isolated-fixture-restoration' });
});
after(async () => { await pool.end(); await administration.query('DROP SCHEMA ' + schema + ' CASCADE'); await administration.end(); });
async function person(role = 'user', tenant) {
  tenant = tenant || await provisionTenant(database, schema, { enabled: true }); const userId = randomUUID(); const subject = 'owned-policy-' + randomUUID();
  await pool.query('INSERT INTO users(id,username,email) VALUES($1,$2,$3)', [userId, subject, subject + '@test.invalid']); await pool.query('INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES($1,$2,$3)', [issuer, subject, userId]);
  await adoptTenant(database, schema, tenant, [{ kind: 'user', resourceId: userId }]); await bootstrapRole(database, { userId, role, duration: 3600, reason: 'Explicit finite isolated owned policy fixture authority' });
  return { tenant, userId, subject };
}
async function candidate(actor, change = () => {}) {
  const inventory = (await pool.query('SELECT identity_authority_inventory($1,$2) AS data', [actor.tenant, issuer])).rows[0].data;
  const inventorySha256 = (await pool.query('SELECT identity_authority_hash($1::jsonb) AS digest', [JSON.stringify(inventory)])).rows[0].digest;
  const body = { schemaVersion: 1, tenantId: actor.tenant, expectedTenantVersion: inventory.tenant.version, expectedTenantGeneration: inventory.tenant.generation, issuer,
    reviewAnchorUserId: actor.userId, inventorySha256, policies: ROLES.map(role => ({ role, authentication: { required: true, maxAgeSeconds: 300 }, activation: { required: false, maxDurationSeconds: 28800, reviewerUserIds: [] }, review: null })),
    sources: inventory.sources.map(source => ({ kind: source.kind, id: source.id, disposition: 'quarantine' })), reason: 'Explicit non-authorizing namespace policy review and sealing' };
  change(body, inventory);
  const staged = await database.transaction(async client => { await client.query("SELECT set_config('opendirectory.authority_review','explicit-offline-authority-review',true)"); return (await client.query('SELECT identity_authority_stage($1::jsonb) AS data', [JSON.stringify(body)])).rows[0].data; });
  return { ...staged, body };
}
async function seal(staged, actor, afterSeal, materialize = true) {
  const namespace = await database.transaction(async client => {
    await client.query("SELECT set_config('opendirectory.authority_seal_review','explicit-offline-owned-policy-seal',true)");
    const result = (await client.query('SELECT identity_authority_seal($1,$2,$3) AS data', [staged.id, actor.tenant, issuer])).rows[0].data;
    if (afterSeal) await afterSeal(client, result); return result;
  });
  if (materialize) await bindSources(namespace, actor);
  return namespace;
}
async function bindSources(namespace, actor, afterBind) {
  return database.transaction(async client => {
    await client.query("SELECT set_config('opendirectory.authority_source_review','explicit-offline-owned-source-review',true)");
    const result = (await client.query('SELECT identity_authority_bind_sources($1,$2,$3) AS data', [namespace.namespaceId, actor.tenant, issuer])).rows[0].data;
    if (afterBind) await afterBind(client, result); return result;
  });
}
async function sourceData(namespace, actor, client = pool) { return (await client.query('SELECT identity_authority_owned_source_data($1,$2,$3) AS data', [namespace.namespaceId, actor.tenant, issuer])).rows[0].data; }
async function sourceCount() { return (await pool.query('SELECT count(*)::int AS count FROM identity_authority_source_sets')).rows[0].count; }
async function policy(namespace, actor, role = 'license-manager', client = pool) { return (await client.query('SELECT identity_authority_owned_policy($1,$2,$3,$4) AS data', [namespace.namespaceId, actor.tenant, issuer, role])).rows[0].data; }
async function count() { return (await pool.query('SELECT count(*)::int AS count FROM identity_authority_namespaces')).rows[0].count; }
function adoptReviewed(body, inventory) {
  body.sources = inventory.sources.map(source => ({ kind: source.kind, id: source.id,
    disposition: source.live && ['canonical-home-coherent', 'offline-review-required'].includes(source.origin) ? 'adopt' : 'quarantine',
    ...(source.live && source.origin === 'offline-review-required' ? { acceptOfflineOrigin: true } : {}) }));
}
async function evidence(namespace, actor, recipient = actor.userId, client = pool) { return (await client.query('SELECT identity_authority_owned_role_evidence($1,$2,$3,$4) AS data', [namespace.namespaceId, actor.tenant, issuer, recipient])).rows[0].data; }
function actorContext(actor) { return JSON.stringify({ issuer, subject: actor.subject, userId: actor.userId }); }
async function grant(actor, recipient, role = 'license-manager', seconds = 300) {
  return database.transaction(async client => (await client.query('INSERT INTO identity_role_assignments(user_id,role,reason,expires_at) VALUES($1,$2,$3,clock_timestamp()+$4*interval \'1 second\') RETURNING *',
    [recipient.userId, role, 'Actual finite owned source for canonical SQL resolver tests', seconds])).rows[0], { actor: actorContext(actor) });
}
async function proof(actor) {
  const state = await new AuthorizationState(database).state(issuer, actor.subject);
  return { iss: issuer, sub: actor.subject, actor_type: 'user', roles: state.roles, identity_authorization: state.context, jti: randomUUID(), exp: Math.floor(Date.now() / 1000) + 300 };
}
async function activePim(actor, recipient) {
  const store = new PrivilegedActivation(database, { revalidate: async () => {} }); const operator = await proof(actor); const user = await proof(recipient);
  const eligibility = await store.grantEligibility({ userId: recipient.userId, role: 'license-manager', maxDurationSeconds: 300, validForSeconds: 3600, reason: 'Actual owned eligibility before independent approval and activation' }, operator);
  const request = await store.request({ id: randomUUID(), eligibilityId: eligibility.id, durationSeconds: 300, reason: 'Actual owned activation request retained by the SQL source resolver' }, user);
  await store.change(request.id, 'approve', operator); const authTime = Math.floor(Date.now() / 1000);
  Object.assign(user, { auth_time: authTime, amr: ['pwd', 'otp'], mfa_authorization: { schemaVersion: 1, userId: recipient.userId, revision: '1', methods: ['pwd', 'otp'], authTime } });
  const active = await store.change(request.id, 'activate', user); return { eligibility, request, active };
}
async function recurring(actor, recipient, reviewer, window = 300, interval = 3600) {
  const assignment = await grant(actor, recipient);
  const rule = await database.transaction(async client => {
    await client.query("SELECT set_config('opendirectory.review_reason','Actual owned retained recurring lease for SQL source resolution',true)");
    return (await client.query("INSERT INTO identity_role_review_policies(role,interval_seconds,window_seconds,reviewer_user_ids) VALUES('license-manager',$1,$2,$3) RETURNING *", [interval, window, [reviewer.userId]])).rows[0];
  }, { actor: actorContext(actor) });
  return { assignment, rule, lease: (await pool.query("SELECT * FROM identity_role_review_leases WHERE target_kind='assignment' AND target_id=$1", [assignment.id])).rows[0] };
}
function reviewedProfile(body, inventory, reviewer, window = 300, interval = 3600) {
  adoptReviewed(body, inventory); body.policies.find(profile => profile.role === 'license-manager').review = { intervalSeconds: interval, windowSeconds: window, reviewerUserIds: [reviewer.userId] };
}

test('a committed complete draft creates a distinct immutable owned namespace with three independently keyed component versions', async () => {
  const actor = await person('admin'); const before = await new AuthorizationState(database).state(issuer, actor.subject); const staged = await candidate(actor); const namespace = await seal(staged, actor);
  assert.notEqual(namespace.namespaceId, staged.id); assert.equal(namespace.candidateId, staged.id); assert.equal(namespace.state, 'sealed'); assert.equal(namespace.canAuthorize, false); assert.equal(namespace.policyCount, ROLES.length);
  for (const table of ['identity_owned_role_authentication', 'identity_owned_role_activation', 'identity_owned_role_reviews', 'identity_owned_role_policies']) assert.equal((await pool.query('SELECT count(*)::int AS count FROM ' + table + ' WHERE namespace_id=$1', [namespace.namespaceId])).rows[0].count, ROLES.length);
  const value = await policy(namespace, actor); assert.equal(value.canAuthorize, false); assert.equal(value.state, 'sealed'); assert.equal(value.policy.authentication.version, '1'); assert.equal(value.policy.activation.version, '1'); assert.equal(value.policy.review.version, '1');
  assert.equal(value.policy.review.required, false); assert.equal(value.policy.review.intervalSeconds, null); assert.deepEqual(value.policy.review.reviewerUserIds, []);
  assert.deepEqual(await new AuthorizationState(database).state(issuer, actor.subject), before);
  const evidence = (await pool.query('SELECT event.actor,event.details,outbox.status FROM identity_authority_namespace_events event JOIN identity_authority_namespace_outbox outbox USING(id) WHERE id=$1', [namespace.namespaceId])).rows[0];
  assert.equal(evidence.actor.kind, 'offline-owned-policy-seal'); assert.equal(evidence.actor.reviewAnchorUserId, actor.userId); assert.equal(evidence.details.canAuthorize, false); assert.equal(evidence.status, 'pending');
});
test('the same catalog role has different owned policy keys and settings in two genuinely distinct tenant namespaces', async () => {
  const own = await person(); const foreign = await person(); const first = await seal(await candidate(own), own); const second = await seal(await candidate(foreign, body => { body.policies.find(profile => profile.role === 'license-manager').authentication = { required: false, maxAgeSeconds: 3600 }; }), foreign);
  assert.equal((await policy(first, own)).policy.authentication.required, true); assert.equal((await policy(second, foreign)).policy.authentication.required, false);
  await assert.rejects(policy(first, foreign), error => error.code === '23503'); await assert.rejects(policy(second, own), error => error.code === '23503');
  await assert.rejects(pool.query('SELECT identity_authority_owned_policy($1,$2,$3,$4)', [first.namespaceId, own.tenant, 'https://wrong-issuer.test', 'license-manager']), error => error.code === '23503');
});
test('later legacy global authentication and activation changes cannot rewrite or supply fallback for the owned policy components', async () => {
  const actor = await person(); const namespace = await seal(await candidate(actor), actor); const before = await policy(namespace, actor);
  await database.transaction(async client => {
    await client.query("SELECT set_config('opendirectory.authentication_reason','Explicit legacy global setting changes must not mutate owned policy',true),set_config('opendirectory.activation_reason','Explicit legacy global setting changes must not mutate owned policy',true)");
    await client.query("UPDATE identity_role_authentication SET mfa_required=true,max_age_seconds=600,version=version+1 WHERE role='license-manager'");
    await client.query("UPDATE identity_role_activation_policies SET activation_required=true,max_duration_seconds=300,version=version+1 WHERE role='license-manager'");
  }, { actor: 'isolated-legacy-setting-change' });
  assert.deepEqual(await policy(namespace, actor), before); await assert.rejects(policy(namespace, actor, 'made-up-role'), error => error.code === '23503');
});
test('unscoped raw writes, an active flip and mutable policy heads cannot manufacture owned governance', async () => {
  const actor = await person(); const namespace = await seal(await candidate(actor), actor);
  for (const sql of ["UPDATE identity_authority_namespaces SET state='active'", 'DELETE FROM identity_authority_namespaces', "UPDATE identity_owned_role_authentication SET required=false WHERE role='license-manager'", 'UPDATE identity_owned_role_policies SET authentication_version=2', 'DELETE FROM identity_owned_role_activation', "UPDATE identity_authority_namespace_outbox SET status='sent'"])
    await assert.rejects(pool.query(sql), error => error.code === '42501');
  await assert.rejects(pool.query("INSERT INTO identity_owned_role_authentication(namespace_id,tenant_id,role,version,required,max_age_seconds) VALUES($1,$2,'license-manager',2,false,3600)", [namespace.namespaceId, actor.tenant]), error => error.code === '42501');
});
test('a committed draft cannot be silently rebased after user or tenant authority changes', async () => {
  const actor = await person(); const staged = await candidate(actor); await pool.query('UPDATE users SET authorization_revision=authorization_revision+1 WHERE id=$1', [actor.userId]);
  await assert.rejects(seal(staged, actor), error => error.code === '42501'); assert.equal(await count(), 0);
  const current = await candidate(actor); await enableTenant(database, schema, actor.tenant, false); await enableTenant(database, schema, actor.tenant, true); await assert.rejects(seal(current, actor), error => error.code === '42501');
});
test('missing exact root, component, deferred or no-effects guards prevent any partial namespace', async () => {
  const actor = await person(); const staged = await candidate(actor);
  for (const [table, trigger] of [['identity_authority_namespaces', 'identity_authority_namespace_guard'], ['identity_owned_role_reviews', 'identity_authority_namespace_guard'], ['identity_authority_namespaces', 'identity_authority_namespace_commit'], ['users', 'aaa_identity_authority_seal_no_effects'], ['groups', 'aaa_identity_authority_seal_no_truncate']]) {
    await pool.query('ALTER TABLE ' + table + ' DISABLE TRIGGER ' + trigger);
    try { await assert.rejects(seal(staged, actor), error => error.code === '42501'); } finally { await pool.query('ALTER TABLE ' + table + ' ENABLE TRIGGER ' + trigger); }
  }
  assert.equal(await count(), 0);
});
test('clearing local scope cannot hide a late live identity effect or turn off deferred receiving validation', async () => {
  const actor = await person(); const foreign = await person(); const staged = await candidate(actor);
  await assert.rejects(seal(staged, actor, client => client.query("SELECT set_config('opendirectory.authority_seal','',true)")), error => error.code === '42501');
  await assert.rejects(seal(staged, actor, async client => { await client.query("SELECT set_config('opendirectory.authority_seal','',true)"); await client.query("UPDATE users SET title='Unrequested sealed policy side effect' WHERE id=$1", [foreign.userId]); }), error => error.code === '42501');
  assert.equal((await pool.query('SELECT title FROM users WHERE id=$1', [foreign.userId])).rows[0].title, null); assert.equal(await count(), 0);
});
test('earlier unrelated live writes cannot ride a later seal in the same transaction', async () => {
  const actor = await person(); const staged = await candidate(actor); const groupId = randomUUID(); await pool.query('INSERT INTO groups(id,name) VALUES($1,$2)', [groupId, 'Original unrelated group']);
  await assert.rejects(database.transaction(async client => {
    await client.query("UPDATE groups SET name='Unrequested pre-seal write' WHERE id=$1", [groupId]); await client.query("SELECT set_config('opendirectory.authority_seal_review','explicit-offline-owned-policy-seal',true)");
    await client.query('SELECT identity_authority_seal($1,$2,$3)', [staged.id, actor.tenant, issuer]);
  }), error => error.code === '42501' && error.message.includes('fresh transaction'));
  assert.equal((await pool.query('SELECT name FROM groups WHERE id=$1', [groupId])).rows[0].name, 'Original unrelated group'); assert.equal(await count(), 0);
});
test('a late receiving trigger cannot weaken component content after its exact row admission', async () => {
  const actor = await person(); const staged = await candidate(actor);
  await pool.query("CREATE FUNCTION late_owned_policy_change() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.role='license-manager' THEN NEW.required=false;END IF;RETURN NEW;END;$$;CREATE TRIGGER zzz_late_owned_policy_change BEFORE INSERT ON identity_owned_role_authentication FOR EACH ROW EXECUTE FUNCTION late_owned_policy_change()");
  try { await assert.rejects(seal(staged, actor), error => error.code === '42501'); } finally { await pool.query('DROP TRIGGER zzz_late_owned_policy_change ON identity_owned_role_authentication;DROP FUNCTION late_owned_policy_change()'); }
  assert.equal(await count(), 0);
});
test('lost outbox or altered retained policy evidence is an unavailable namespace, never an empty permissive policy', async () => {
  const actor = await person(); const namespace = await seal(await candidate(actor), actor);
  await pool.query('ALTER TABLE identity_authority_namespace_outbox RENAME TO withheld_owned_outbox');
  try { await assert.rejects(policy(namespace, actor)); } finally { await pool.query('ALTER TABLE withheld_owned_outbox RENAME TO identity_authority_namespace_outbox'); }
  await pool.query('ALTER TABLE identity_authority_candidate_outbox RENAME TO withheld_candidate_outbox');
  try { await assert.rejects(policy(namespace, actor)); } finally { await pool.query('ALTER TABLE withheld_candidate_outbox RENAME TO identity_authority_candidate_outbox'); }
  await pool.query('ALTER TABLE identity_authority_namespace_events DISABLE TRIGGER identity_authority_namespace_guard');
  try { await pool.query("UPDATE identity_authority_namespace_events SET actor='{}' WHERE id=$1", [namespace.namespaceId]); } finally { await pool.query('ALTER TABLE identity_authority_namespace_events ENABLE TRIGGER identity_authority_namespace_guard'); }
  await assert.rejects(policy(namespace, actor), error => error.code === '42501');
});
test('sealing and reading are stable across actual SQL session time zones and preserve above-safe-integer generations', async () => {
  const actor = await person(); await pool.query("SELECT setval('identity_authority_namespace_generation',9007199254740993,true)"); const staged = await candidate(actor);
  const namespace = await database.transaction(async client => { await client.query("SET LOCAL timezone='Europe/Zurich'"); await client.query("SELECT set_config('opendirectory.authority_seal_review','explicit-offline-owned-policy-seal',true)"); return (await client.query('SELECT identity_authority_seal($1,$2,$3) AS data', [staged.id, actor.tenant, issuer])).rows[0].data; });
  assert.ok(BigInt(namespace.generation) > BigInt(Number.MAX_SAFE_INTEGER)); const original = await policy(namespace, actor);
  const elsewhere = await database.transaction(async client => { await client.query("SET LOCAL timezone='Pacific/Honolulu'"); return policy(namespace, actor, 'license-manager', client); }, { readOnly: true }); assert.deepEqual(elsewhere, original);
});
test('physical expiry after owned-policy DML rolls back the namespace, all components and its pending evidence', async () => {
  const actor = await person('admin'); const recipient = await person('user', actor.tenant); let source;
  await database.transaction(async client => { source = (await client.query("INSERT INTO identity_role_assignments(user_id,role,reason,expires_at) VALUES($1,'license-reader','Actual short source constrains owned-policy sealing',clock_timestamp()+interval '2 seconds') RETURNING id", [recipient.userId])).rows[0].id; }, { actor: JSON.stringify({ issuer, subject: actor.subject, userId: actor.userId }) });
  const staged = await candidate(actor, body => { body.sources.find(entry => entry.id === source).disposition = 'adopt'; });
  await assert.rejects(seal(staged, actor, client => client.query('SELECT pg_sleep(2.1)')), error => error.code === '42501'); assert.equal(await count(), 0);
});
test('a real limited login and an assumed role cannot seal or read owner-only policy content through a definer', async () => {
  const actor = await person(); const staged = await candidate(actor); const namespace = await seal(staged, actor); const role = 'owned_policy_limited_' + randomUUID().replaceAll('-', ''); let limited;
  await administration.query(`CREATE ROLE ${role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS`);
  try {
    await pool.query(`GRANT USAGE ON SCHEMA ${schema} TO ${role};GRANT EXECUTE ON FUNCTION identity_authority_seal(uuid,uuid,text),identity_authority_owned_policy(uuid,uuid,text,text) TO ${role}`);
    const address = new URL(process.env.IDENTITY_TEST_DATABASE_URL); address.username = role; limited = new Pool({ connectionString: address.toString(), max: 1, options: `-c search_path=${schema},public` });
    for (const assumed of [false, true]) for (const read of [false, true]) {
      const client = await (assumed ? pool : limited).connect();
      try { await client.query('BEGIN'); if (assumed) await client.query('SET LOCAL ROLE ' + role); await client.query("SELECT set_config('opendirectory.authority_seal_review','explicit-offline-owned-policy-seal',true)");
        await assert.rejects(read ? policy(namespace, actor, 'license-manager', client) : client.query('SELECT identity_authority_seal($1,$2,$3)', [staged.id, actor.tenant, issuer]), error => error.code === '42501' && error.message === 'Actual database owner required for offline authority review');
      } finally { await client.query('ROLLBACK'); client.release(); }
    }
  } finally { await limited?.end(); await pool.query('DROP OWNED BY ' + role); await administration.query('DROP ROLE ' + role); }
});
test('migration replay preserves namespace identity, all component versions and exact evidence without activating public authority', async () => {
  const actor = await person('admin'); const staged = await candidate(actor); const namespace = await seal(staged, actor); const before = await policy(namespace, actor); const live = await new AuthorizationState(database).state(issuer, actor.subject);
  await pool.query(fs.readFileSync(path.join(migrations, '033_owned_authority_policy_storage.sql'), 'utf8')); assert.deepEqual(await policy(namespace, actor), before); assert.equal(await count(), 1);
  assert.deepEqual(await new AuthorizationState(database).state(issuer, actor.subject), live); await assert.rejects(seal(staged, actor), error => error.code === '23505');
});
test('an uncommitted draft cannot be sealed in its staging transaction even after the caller changes review markers', async () => {
  const actor = await person(); const staged = await candidate(actor); const body = { ...staged.body, reason: 'Second distinct draft must commit before owned-policy sealing' };
  await assert.rejects(database.transaction(async client => {
    await client.query("SELECT set_config('opendirectory.authority_review','explicit-offline-authority-review',true)");
    const next = (await client.query('SELECT identity_authority_stage($1::jsonb) AS data', [JSON.stringify(body)])).rows[0].data;
    await client.query("SELECT set_config('opendirectory.authority_seal_review','explicit-offline-owned-policy-seal',true),set_config('opendirectory.authority_stage','',true)");
    await client.query('SELECT identity_authority_seal($1,$2,$3)', [next.id, actor.tenant, issuer]);
  }), error => error.code === '42501'); assert.equal(await count(), 0);
});
test('explicit owned protected activation and recurring review settings normalize without creating live review leases or duty proofs', async () => {
  const actor = await person('admin'); const approver = await person('pim-approver', actor.tenant); const reviewer = await person('access-reviewer', actor.tenant);
  const staged = await candidate(actor, body => {
    body.policies.find(profile => profile.role === 'admin').activation = { required: true, maxDurationSeconds: 300, reviewerUserIds: [approver.userId] };
    body.policies.find(profile => profile.role === 'license-manager').review = { intervalSeconds: 3600, windowSeconds: 300, reviewerUserIds: [reviewer.userId] };
  });
  const namespace = await seal(staged, actor); const activation = (await policy(namespace, actor, 'admin')).policy.activation; const review = (await policy(namespace, actor)).policy.review;
  assert.equal(activation.required, true); assert.equal(activation.maxDurationSeconds, 300); assert.deepEqual(activation.reviewerUserIds, [approver.userId]);
  assert.equal(review.required, true); assert.equal(review.intervalSeconds, 3600); assert.equal(review.windowSeconds, 300); assert.deepEqual(review.reviewerUserIds, [reviewer.userId]);
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_role_review_leases')).rows[0].count, 0); assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_pim_requests')).rows[0].count, 0);
});
test('a known foreign candidate is rejected before locks and sealing an owned namespace never waits on a foreign user', async () => {
  const actor = await person(); const foreign = await person(); const staged = await candidate(actor); const blocker = await pool.connect();
  try {
    await blocker.query('BEGIN'); await blocker.query('SELECT id FROM users WHERE id=$1 FOR UPDATE', [foreign.userId]); const started = Date.now();
    await assert.rejects(seal(staged, foreign), error => error.code === '23503'); const namespace = await seal(staged, actor); assert.equal(namespace.tenantId, actor.tenant); assert.ok(Date.now() - started < 2000);
  } finally { await blocker.query('ROLLBACK'); blocker.release(); }
});
test('neither earlier nor late canonical truncation can ride a sealed namespace transaction', async () => {
  const actor = await person(); const staged = await candidate(actor);
  await assert.rejects(database.transaction(async client => { await client.query('TRUNCATE group_members'); await client.query("SELECT set_config('opendirectory.authority_seal_review','explicit-offline-owned-policy-seal',true)"); await client.query('SELECT identity_authority_seal($1,$2,$3)', [staged.id, actor.tenant, issuer]); }), error => error.code === '42501');
  await assert.rejects(seal(staged, actor, async client => { await client.query("SELECT set_config('opendirectory.authority_seal','',true)"); await client.query('TRUNCATE group_members'); }), error => error.code === '42501'); assert.equal(await count(), 0);
});
test('owned policy inspection cannot confirm an uncommitted namespace before its deferred receiving validation', async () => {
  const actor = await person(); const staged = await candidate(actor);
  await assert.rejects(seal(staged, actor, (client, namespace) => policy(namespace, actor, 'license-manager', client)), error => error.code === '42501' && error.message === 'A committed sealed namespace is required');
  assert.equal(await count(), 0);
});

test('the canonical SQL source kernel resolves exact retained owned assignments and separate typed policy keys without activating authority', async () => {
  const actor = await person('admin'); const recipient = await person('user', actor.tenant); const assignment = await grant(actor, recipient); const live = await new AuthorizationState(database).state(issuer, recipient.subject);
  const namespace = await seal(await candidate(actor, adoptReviewed), actor); const result = await evidence(namespace, actor, recipient.userId);
  assert.equal(result.canAuthorize, false); assert.equal(result.state, 'sealed'); assert.equal(result.schemaVersion, 2); assert.equal(result.namespaceId, namespace.namespaceId);
  assert.deepEqual(result.proposedRoles, ['license-manager', 'user']); assert.equal(result.recipientActive, true); assert.match(result.proposedRolesRevision, /^[a-f0-9]{64}$/);
  const source = result.grants.find(source => source.id === assignment.id); assert.equal(source.authenticationVersion, '1'); assert.equal(source.activationVersion, '1'); assert.equal(source.reviewVersion, '1');
  assert.equal(source.sources[0][0], 'assignment:' + assignment.id); assert.ok(Date.parse(source.validUntil) <= assignment.expires_at.getTime());
  assert.deepEqual(result.authentication, { required: true, maxAgeSeconds: 300 }); assert.equal(Object.hasOwn(result, 'roles'), false); assert.equal(Object.hasOwn(result, 'context'), false);
  assert.deepEqual(await new AuthorizationState(database).state(issuer, recipient.subject), live);
});
test('owned source resolution selects the explicit namespace and known owner before any foreign recipient lock', async () => {
  const own = await person('license-manager'); const foreign = await person('license-manager'); const first = await seal(await candidate(own, adoptReviewed), own);
  const second = await seal(await candidate(foreign, (body, inventory) => { adoptReviewed(body, inventory); body.policies.find(profile => profile.role === 'license-manager').authentication = { required: false, maxAgeSeconds: 3600 }; }), foreign);
  const blocker = await pool.connect();
  try {
    await blocker.query('BEGIN'); await blocker.query('SELECT id FROM users WHERE id=$1 FOR UPDATE', [foreign.userId]); const start = Date.now();
    await assert.rejects(evidence(first, foreign), error => error.code === '23503'); await assert.rejects(evidence(first, own, foreign.userId), error => error.code === '23503');
    assert.equal((await evidence(first, own)).authentication.required, true); assert.equal((await evidence(second, foreign)).authentication.required, false); assert.ok(Date.now() - start < 2000);
    await assert.rejects(pool.query('SELECT identity_authority_owned_role_evidence($1,$2,$3,$4)', [first.namespaceId, own.tenant, 'https://foreign-issuer.test', own.userId]), error => error.code === '23503');
  } finally { await blocker.query('ROLLBACK'); blocker.release(); }
});
test('unknown and imported foreign origins remain quarantined despite a canonical enabled recipient and familiar role name', async () => {
  const actor = await person('admin'); const foreign = await person('admin');
  await pool.query("INSERT INTO identity_role_assignments(user_id,role,reason,expires_at) VALUES($1,'license-reader','Deliberately unresolved legacy source must remain quarantined',clock_timestamp()+interval '5 minutes')", [actor.userId]);
  await pool.query('ALTER TABLE identity_role_assignments DISABLE TRIGGER aaa_identity_authority_target_tenant');
  try { await grant(foreign, actor); } finally { await pool.query('ALTER TABLE identity_role_assignments ENABLE TRIGGER aaa_identity_authority_target_tenant'); }
  const namespace = await seal(await candidate(actor, adoptReviewed), actor); const result = await evidence(namespace, actor);
  assert.deepEqual(result.proposedRoles, ['admin']); assert.ok(result.assignments.filter(source => source.role !== 'admin').every(source => source.issue === 'quarantined_component'));
});
test('legacy global MFA and activation edits do not supply, withdraw or rewrite sealed owned source governance', async () => {
  const actor = await person('license-manager'); const namespace = await seal(await candidate(actor, adoptReviewed), actor); const before = await evidence(namespace, actor);
  await database.transaction(async client => {
    await client.query("SELECT set_config('opendirectory.authentication_reason','Legacy global change is not owned policy authority',true),set_config('opendirectory.activation_reason','Legacy global change is not owned policy authority',true)");
    await client.query("UPDATE identity_role_authentication SET mfa_required=true,max_age_seconds=600,version=version+1 WHERE role='license-manager'");
    await client.query("UPDATE identity_role_activation_policies SET activation_required=true,max_duration_seconds=60,version=version+1 WHERE role='license-manager'");
  }, { actor: actorContext(actor) });
  assert.deepEqual(await evidence(namespace, actor), before); assert.deepEqual((await new AuthorizationState(database).state(issuer, actor.subject)).roles, []);
});
test('a newly written unreviewed legacy grant cannot enter the retained namespace through a recipient-derived fallback', async () => {
  const actor = await person('admin'); const recipient = await person('user', actor.tenant); const namespace = await seal(await candidate(actor, adoptReviewed), actor);
  const before = await evidence(namespace, actor, recipient.userId); const unreviewed = await grant(actor, recipient);
  const after = await evidence(namespace, actor, recipient.userId); assert.deepEqual(after.proposedRoles, ['user']); assert.equal(after.grants.some(source => source.id === unreviewed.id), false);
  assert.equal(after.assignments.length, before.assignments.length);
});
test('exact source withdrawal closes only its retained component without refreshing hashes or removing unrelated roles', async () => {
  const actor = await person('admin'); const recipient = await person('user', actor.tenant); const manager = await grant(actor, recipient); await grant(actor, recipient, 'license-reader');
  const namespace = await seal(await candidate(actor, adoptReviewed), actor); const before = await evidence(namespace, actor, recipient.userId);
  await database.transaction(client => client.query('UPDATE identity_role_assignments SET revoked_at=clock_timestamp() WHERE id=$1', [manager.id]), { actor: actorContext(actor) });
  const after = await evidence(namespace, actor, recipient.userId); assert.deepEqual(after.proposedRoles, ['license-reader', 'user']); assert.notEqual(after.proposedRolesRevision, before.proposedRolesRevision);
  assert.equal(after.assignments.find(source => source.id === manager.id).issue, 'source_changed');
});
test('altered retained grant evidence is unavailable even when the assignment state and recipient still match', async () => {
  const actor = await person('license-manager'); const namespace = await seal(await candidate(actor, adoptReviewed), actor);
  await pool.query('ALTER TABLE identity_role_audit DISABLE TRIGGER identity_role_audit_guard');
  try { await pool.query("UPDATE identity_role_audit SET actor='altered-source-origin' WHERE user_id=$1", [actor.userId]); } finally { await pool.query('ALTER TABLE identity_role_audit ENABLE TRIGGER identity_role_audit_guard'); }
  const result = await evidence(namespace, actor); assert.deepEqual(result.proposedRoles, []); assert.equal(result.assignments[0].issue, 'source_changed');
});
test('a real approved and activated PIM component satisfies owned mandatory activation only with all original IDs and bounds', async () => {
  const actor = await person('admin'); const recipient = await person('user', actor.tenant); const pim = await activePim(actor, recipient);
  const namespace = await seal(await candidate(actor, (body, inventory) => { adoptReviewed(body, inventory); body.policies.find(profile => profile.role === 'license-manager').activation = { required: true, maxDurationSeconds: 300, reviewerUserIds: [] }; }), actor);
  const result = await evidence(namespace, actor, recipient.userId); assert.deepEqual(result.proposedRoles, ['license-manager', 'user']);
  const source = result.grants.find(source => source.id === pim.active.assignmentId); assert.deepEqual(source.sources.map(source => source[0]).sort(), ['assignment:' + pim.active.assignmentId, 'eligibility:' + pim.eligibility.id, 'request:' + pim.request.id].sort());
  assert.ok(Date.parse(source.validUntil) <= Date.parse(pim.active.expiresAt));
});
test('an active PIM assignment resolves through both retained assignment and eligibility review leases in the same owned component', async () => {
  const actor = await person('admin'); const recipient = await person('user', actor.tenant); const reviewer = await person('access-reviewer', actor.tenant); await recurring(actor, recipient, reviewer);
  const pim = await activePim(actor, recipient);
  const namespace = await seal(await candidate(actor, (body, inventory) => { reviewedProfile(body, inventory, reviewer); body.policies.find(profile => profile.role === 'license-manager').activation.required = true; }), actor);
  const result = await evidence(namespace, actor, recipient.userId); const source = result.grants.find(source => source.id === pim.active.assignmentId); assert.ok(source);
  const leases = (await pool.query("SELECT * FROM identity_role_review_leases WHERE user_id=$1 AND (target_id=$2 OR target_id=$3) ORDER BY id", [recipient.userId, pim.active.assignmentId, pim.eligibility.id])).rows;
  assert.equal(leases.length, 2); assert.deepEqual(source.sources.filter(source => source[0].startsWith('review:')).map(source => source[0]).sort(), leases.map(lease => 'review:' + lease.id).sort());
  assert.ok(Date.parse(source.validUntil) <= Math.min(...leases.map(lease => lease.deadline_at.getTime())));
});
test('revoking actual PIM eligibility makes its whole original activation component negative', async () => {
  const actor = await person('admin'); const recipient = await person('user', actor.tenant); const pim = await activePim(actor, recipient); const namespace = await seal(await candidate(actor, adoptReviewed), actor);
  assert.ok((await evidence(namespace, actor, recipient.userId)).proposedRoles.includes('license-manager'));
  await new PrivilegedActivation(database, { revalidate: async () => {} }).revokeEligibility(pim.eligibility.id, await proof(actor)); const after = await evidence(namespace, actor, recipient.userId);
  assert.deepEqual(after.proposedRoles, ['user']); assert.equal(after.assignments.find(source => source.id === pim.active.assignmentId).eligibleForAdoption, false);
});
test('new owned mandatory PIM and tighter duration do not relabel a retained direct grant as compliant', async () => {
  const actor = await person('license-manager');
  const activation = await seal(await candidate(actor, (body, inventory) => { adoptReviewed(body, inventory); body.policies.find(profile => profile.role === 'license-manager').activation.required = true; }), actor);
  assert.equal((await evidence(activation, actor)).assignments[0].issue, 'owned_activation_required');
  const duration = await seal(await candidate(actor, (body, inventory) => { adoptReviewed(body, inventory); body.policies.find(profile => profile.role === 'license-manager').activation.maxDurationSeconds = 60; }), actor);
  assert.equal((await evidence(duration, actor)).assignments[0].issue, 'duration_requires_new_grant');
});
test('new mandatory owned review cannot invent an approving lease for an otherwise exact direct assignment', async () => {
  const actor = await person('admin'); const recipient = await person('license-manager', actor.tenant); const reviewer = await person('access-reviewer', actor.tenant);
  const namespace = await seal(await candidate(actor, (body, inventory) => reviewedProfile(body, inventory, reviewer)), actor); const result = await evidence(namespace, actor, recipient.userId);
  assert.deepEqual(result.proposedRoles, []); assert.equal(result.assignments[0].issue, 'owned_review_required'); assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_role_review_leases')).rows[0].count, 0);
});
test('owned recurring resolution preserves actual source, cycle, lease and tighter original deadline without resetting time', async () => {
  const actor = await person('admin'); const recipient = await person('user', actor.tenant); const reviewer = await person('access-reviewer', actor.tenant); const retained = await recurring(actor, recipient, reviewer);
  const namespace = await seal(await candidate(actor, (body, inventory) => reviewedProfile(body, inventory, reviewer, 60)), actor); const result = await evidence(namespace, actor, recipient.userId);
  const source = result.grants.find(source => source.id === retained.assignment.id); assert.ok(source); assert.equal(Date.parse(source.validUntil), retained.lease.due_at.getTime() + 60000);
  assert.deepEqual(source.sources.map(source => source[0]).sort(), ['assignment:' + retained.assignment.id, 'review:' + retained.lease.id].sort());
  assert.deepEqual((await pool.query('SELECT * FROM identity_role_review_leases WHERE id=$1', [retained.lease.id])).rows[0], retained.lease);
});
test('retiring a legacy global review policy does not rewrite sealed owned schedules or immutable reviewed origins', async () => {
  const actor = await person('admin'); const recipient = await person('user', actor.tenant); const reviewer = await person('access-reviewer', actor.tenant); const retained = await recurring(actor, recipient, reviewer);
  const namespace = await seal(await candidate(actor, (body, inventory) => reviewedProfile(body, inventory, reviewer)), actor); const before = await evidence(namespace, actor, recipient.userId);
  await database.transaction(async client => { await client.query("SELECT set_config('opendirectory.review_reason','Legacy retirement is provenance not owned governance authority',true)"); await client.query('UPDATE identity_role_review_policies SET retired_at=clock_timestamp(),version=version+1 WHERE id=$1', [retained.rule.id]); }, { actor: actorContext(actor) });
  assert.deepEqual(await evidence(namespace, actor, recipient.userId), before);
});
test('a newly attached unreviewed lease cannot be ignored just because an old assignment hash still matches', async () => {
  const actor = await person('admin'); const recipient = await person('user', actor.tenant); const reviewer = await person('access-reviewer', actor.tenant); const assignment = await grant(actor, recipient);
  const namespace = await seal(await candidate(actor, adoptReviewed), actor);
  await database.transaction(async client => { await client.query("SELECT set_config('opendirectory.review_reason','Actual later global lease is not an adopted owned component',true)"); await client.query("INSERT INTO identity_role_review_policies(role,interval_seconds,window_seconds,reviewer_user_ids) VALUES('license-manager',3600,300,$1)", [[reviewer.userId]]); }, { actor: actorContext(actor) });
  const result = await evidence(namespace, actor, recipient.userId); assert.deepEqual(result.proposedRoles, ['user']); assert.equal(result.assignments.find(source => source.id === assignment.id).issue, 'source_changed');
});
for (const cycle of ['3', '9223372036854775807']) test('retained imported review cycle ' + cycle + ' cannot reset an overdue tighter owned recurrence or overflow its arithmetic', async () => {
  const actor = await person('admin'); const recipient = await person('user', actor.tenant); const reviewer = await person('access-reviewer', actor.tenant); const retained = await recurring(actor, recipient, reviewer, 300, 7200);
  await pool.query('ALTER TABLE identity_role_review_leases DISABLE TRIGGER identity_role_review_lease_guard');
  try { await database.transaction(async client => { await client.query("SELECT set_config('opendirectory.review_reason','Controlled retained historical recurrence import, not a public transition',true)"); await client.query("UPDATE identity_role_review_leases SET cycle=$2,version=version+1,due_at=clock_timestamp()+interval '1 hour',deadline_at=clock_timestamp()+interval '1 hour 5 minutes' WHERE id=$1", [retained.lease.id, cycle]); }, { actor: actorContext(actor) }); }
  finally { await pool.query('ALTER TABLE identity_role_review_leases ENABLE TRIGGER identity_role_review_lease_guard'); }
  const namespace = await seal(await candidate(actor, (body, inventory) => reviewedProfile(body, inventory, reviewer)), actor); const result = await evidence(namespace, actor, recipient.userId);
  assert.deepEqual(result.proposedRoles, ['user']); assert.equal(result.assignments.find(source => source.id === retained.assignment.id).issue, 'owned_review_expired');
});
test('disabled or unbound recipients cannot use otherwise exact owned source evidence', async () => {
  const actor = await person('admin'); const recipient = await person('license-manager', actor.tenant); const namespace = await seal(await candidate(actor, adoptReviewed), actor);
  await pool.query('UPDATE users SET enabled=false WHERE id=$1', [recipient.userId]); const disabled = await evidence(namespace, actor, recipient.userId); assert.equal(disabled.recipientActive, false); assert.deepEqual(disabled.proposedRoles, []);
  await pool.query('UPDATE users SET enabled=true WHERE id=$1', [recipient.userId]); await pool.query('DELETE FROM identity_subject_links WHERE user_id=$1', [recipient.userId]); const unbound = await evidence(namespace, actor, recipient.userId); assert.equal(unbound.recipientActive, false); assert.deepEqual(unbound.proposedRoles, []);
});
test('missing sealing evidence and receiving guards fail unavailable rather than returning permissive empty governance', async () => {
  const actor = await person('license-manager'); const namespace = await seal(await candidate(actor, adoptReviewed), actor);
  await pool.query('ALTER TABLE identity_authority_namespace_outbox RENAME TO withheld_source_outbox');
  try { await assert.rejects(evidence(namespace, actor)); } finally { await pool.query('ALTER TABLE withheld_source_outbox RENAME TO identity_authority_namespace_outbox'); }
  await pool.query('ALTER TABLE identity_owned_role_reviews DISABLE TRIGGER identity_authority_namespace_guard');
  try { await assert.rejects(evidence(namespace, actor), error => error.code === '42501'); } finally { await pool.query('ALTER TABLE identity_owned_role_reviews ENABLE TRIGGER identity_authority_namespace_guard'); }
});
test('uncommitted namespaces and subsequently introduced owned recipients are not source bindings', async () => {
  const actor = await person('admin'); const staged = await candidate(actor, adoptReviewed);
  await assert.rejects(seal(staged, actor, (client, namespace) => evidence(namespace, actor, actor.userId, client)), error => error.code === '42501');
  const namespace = await seal(staged, actor); const later = await person('license-manager', actor.tenant); await assert.rejects(evidence(namespace, actor, later.userId), error => error.code === '23503');
});
test('source SQL replay, real session time zones and above-safe-integer namespace generations preserve exact evidence', async () => {
  const actor = await person('license-manager'); await pool.query("SELECT setval('identity_authority_namespace_generation',9007199254741993,true)"); const namespace = await seal(await candidate(actor, adoptReviewed), actor); const before = await evidence(namespace, actor);
  assert.equal(typeof before.namespaceGeneration, 'string'); assert.ok(BigInt(before.namespaceGeneration) > BigInt(Number.MAX_SAFE_INTEGER));
  await pool.query(fs.readFileSync(path.join(migrations, '034_owned_authority_source_resolution.sql'), 'utf8'));
  await pool.query(fs.readFileSync(path.join(migrations, '036_owned_authority_source_bindings.sql'), 'utf8'));
  const elsewhere = await database.transaction(async client => { await client.query("SET LOCAL timezone='Pacific/Honolulu'"); return evidence(namespace, actor, actor.userId, client); }, { readOnly: true }); assert.deepEqual(elsewhere, before);
});
test('a real limited login cannot launder owned source reads through either granted security definer', async () => {
  const actor = await person('license-manager'); const namespace = await seal(await candidate(actor, adoptReviewed), actor); const role = 'owned_source_limited_' + randomUUID().replaceAll('-', ''); let limited;
  await administration.query(`CREATE ROLE ${role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS`);
  try {
    await pool.query(`GRANT USAGE ON SCHEMA ${schema} TO ${role};GRANT EXECUTE ON FUNCTION identity_authority_owned_role_evidence(uuid,uuid,text,uuid),identity_authority_source_observation(text,uuid,uuid,timestamptz) TO ${role}`);
    const address = new URL(process.env.IDENTITY_TEST_DATABASE_URL); address.username = role; limited = new Pool({ connectionString: address.toString(), max: 1, options: `-c search_path=${schema},public` });
    await assert.rejects(evidence(namespace, actor, actor.userId, limited), error => error.code === '42501' && error.message === 'Actual database owner required for offline authority review');
    await assert.rejects(limited.query("SELECT identity_authority_source_observation('assignment',$1,$2,clock_timestamp())", [randomUUID(), actor.tenant]), error => error.code === '42501');
    await database.transaction(async client => { await client.query('SET LOCAL ROLE ' + role); await assert.rejects(evidence(namespace, actor, actor.userId, client), error => error.code === '42501'); throw Object.assign(new Error('Rollback expected failed assumed-role transaction'), { code: 'expected_rollback' }); }).catch(error => { assert.equal(error.code, 'expected_rollback'); });
  } finally { await limited?.end(); await pool.query('DROP OWNED BY ' + role); await administration.query('DROP ROLE ' + role); }
});
test('an expired original source deadline or changed tenant incarnation cannot be rebased by the owned SQL resolver', async () => {
  const actor = await person('admin'); const recipient = await person('user', actor.tenant); await grant(actor, recipient, 'license-manager', 2); const namespace = await seal(await candidate(actor, adoptReviewed), actor);
  assert.ok((await evidence(namespace, actor, recipient.userId)).proposedRoles.includes('license-manager')); await pool.query('SELECT pg_sleep(2.1)'); await assert.rejects(evidence(namespace, actor, recipient.userId), error => error.code === '42501');
  const current = await seal(await candidate(actor, adoptReviewed), actor); await enableTenant(database, schema, actor.tenant, false); await enableTenant(database, schema, actor.tenant, true); await assert.rejects(evidence(current, actor), error => error.code === '42501');
});
test('more than one hundred reviewed positive assignments is unavailable, never silently trimmed to a privileged subset', async () => {
  const actor = await person('admin'); const recipient = await person('user', actor.tenant);
  await database.transaction(client => client.query("INSERT INTO identity_role_assignments(user_id,role,reason,expires_at) SELECT $1,'license-reader','Actual bounded overflow fixture must not be silently trimmed',clock_timestamp()+interval '5 minutes' FROM generate_series(1,100)", [recipient.userId]), { actor: actorContext(actor) });
  const namespace = await seal(await candidate(actor, adoptReviewed), actor); await assert.rejects(evidence(namespace, actor, recipient.userId), error => error.code === '54000');
});

test('a sealed policy namespace cannot supply candidate-JSON fallback before explicit committed source materialization', async () => {
  const actor = await person('license-manager'); const before = await new AuthorizationState(database).state(issuer, actor.subject);
  const namespace = await seal(await candidate(actor, adoptReviewed), actor, undefined, false);
  await assert.rejects(sourceData(namespace, actor), error => error.code === '23503'); await assert.rejects(evidence(namespace, actor), error => error.code === '23503');
  await assert.rejects(pool.query('SELECT identity_authority_bind_sources($1,$2,$3)', [namespace.namespaceId, actor.tenant, issuer]), error => error.code === '42501');
  assert.equal(await sourceCount(), 0); const result = await bindSources(namespace, actor); assert.equal(result.canAuthorize, false); assert.equal(result.state, 'sealed-sources'); assert.equal(result.sourceVersion, '1');
  const resolved = await evidence(namespace, actor); assert.deepEqual(resolved.proposedRoles, ['license-manager']); assert.equal(resolved.sourceSetSha256, result.contentSha256);
  assert.deepEqual(await new AuthorizationState(database).state(issuer, actor.subject), before);
});
test('materialized PIM and both review planes retain every original source, exact typed policy version, ordered edge and pending evidence', async () => {
  const actor = await person('admin'); const recipient = await person('user', actor.tenant); const reviewer = await person('access-reviewer', actor.tenant); await recurring(actor, recipient, reviewer);
  const pim = await activePim(actor, recipient); const staged = await candidate(actor, (body, inventory) => reviewedProfile(body, inventory, reviewer));
  const namespace = await seal(staged, actor); const data = await sourceData(namespace, actor);
  const inventory = (await pool.query('SELECT inventory FROM identity_authority_candidates WHERE id=$1', [staged.id])).rows[0].inventory;
  assert.deepEqual(data.users, inventory.users); assert.equal(data.sources.length, inventory.sources.length);
  const versions = (await pool.query('SELECT * FROM identity_owned_authority_source_versions WHERE namespace_id=$1', [namespace.namespaceId])).rows;
  for (const source of inventory.sources) {
    const retained = versions.find(version => version.kind === source.kind && version.source_id === source.id);
    assert.equal(retained.tenant_id, actor.tenant); assert.equal(retained.source_version, '1'); assert.equal(retained.policy_role, source.role);
    assert.equal(retained.authentication_version, '1'); assert.equal(retained.activation_version, '1'); assert.equal(retained.review_version, '1');
    assert.deepEqual(retained.source_state, source.state); assert.equal(retained.before_sha256, source.beforeSha256);
    assert.deepEqual(data.sources.find(version => version.kind === source.kind && version.id === source.id).relatedSources, source.relatedSources);
  }
  const edges = (await pool.query('SELECT * FROM identity_owned_authority_source_edges WHERE namespace_id=$1', [namespace.namespaceId])).rows;
  assert.ok(edges.length >= 5); assert.ok(edges.every(edge => edge.resolution === 'owned' && edge.related_version === '1'));
  const root = (await pool.query('SELECT * FROM identity_authority_source_sets WHERE namespace_id=$1', [namespace.namespaceId])).rows[0];
  const receipt = (await pool.query('SELECT event.*,outbox.status FROM identity_authority_source_set_events event JOIN identity_authority_source_set_outbox outbox USING(id) WHERE id=$1', [namespace.namespaceId])).rows[0];
  assert.equal(root.source_count, inventory.sources.length); assert.equal(root.content_sha256, data.contentSha256); assert.equal(root.review_anchor_user_id, actor.userId);
  assert.equal(receipt.actor.kind, 'offline-source-materialization'); assert.equal(receipt.actor.reviewAnchorUserId, actor.userId); assert.equal(receipt.details.canAuthorize, false); assert.equal(receipt.status, 'pending');
  const result = await evidence(namespace, actor, recipient.userId); const active = result.grants.find(source => source.id === pim.active.assignmentId); assert.ok(active);
  assert.ok(active.sources.every(source => source.length === 6 && source.slice(2).every(version => version === '1')));
});
test('unsupported historical roles remain typed quarantine with no invented owned-policy key', async () => {
  const actor = await person('admin'); let identifier;
  await pool.query('ALTER TABLE identity_role_assignments DISABLE TRIGGER identity_role_policy_guard');
  try { identifier = (await pool.query("INSERT INTO identity_role_assignments(user_id,role,reason,expires_at) VALUES($1,'retired-unknown-role','Controlled legacy role outside the present catalog',clock_timestamp()+interval '5 minutes') RETURNING id", [actor.userId])).rows[0].id; }
  finally { await pool.query('ALTER TABLE identity_role_assignments ENABLE TRIGGER identity_role_policy_guard'); }
  const namespace = await seal(await candidate(actor, adoptReviewed), actor);
  const row = (await pool.query('SELECT * FROM identity_owned_authority_source_versions WHERE namespace_id=$1 AND source_id=$2', [namespace.namespaceId, identifier])).rows[0];
  assert.equal(row.role, 'retired-unknown-role'); assert.equal(row.disposition, 'quarantine'); assert.equal(row.policy_role, null); assert.equal(row.authentication_version, null); assert.equal(row.activation_version, null); assert.equal(row.review_version, null);
  assert.deepEqual((await evidence(namespace, actor)).proposedRoles, ['admin']);
});
test('a retained foreign graph reference stays unresolved instead of acquiring a beneficiary-derived owned edge', async () => {
  const actor = await person('admin'); const recipient = await person('user', actor.tenant); const reviewer = await person('access-reviewer', actor.tenant); const retained = await recurring(actor, recipient, reviewer);
  const foreign = await person('user'); const foreignSource = (await pool.query('SELECT id FROM identity_role_assignments WHERE user_id=$1', [foreign.userId])).rows[0].id;
  await pool.query('ALTER TABLE identity_role_review_leases DISABLE TRIGGER identity_role_review_lease_guard;ALTER TABLE identity_role_review_leases DISABLE TRIGGER aaa_identity_authority_target_tenant');
  try { await database.transaction(async client => { await client.query("SELECT set_config('opendirectory.review_reason','Controlled imported cross-owner source graph requires quarantine',true)"); await client.query('UPDATE identity_role_review_leases SET target_id=$2,version=version+1 WHERE id=$1', [retained.lease.id, foreignSource]); }, { actor: actorContext(actor) }); }
  finally { await pool.query('ALTER TABLE identity_role_review_leases ENABLE TRIGGER identity_role_review_lease_guard;ALTER TABLE identity_role_review_leases ENABLE TRIGGER aaa_identity_authority_target_tenant'); }
  const namespace = await seal(await candidate(actor, (body, inventory) => { reviewedProfile(body, inventory, reviewer); body.sources.find(source => source.id === retained.lease.id).disposition = 'quarantine'; }), actor);
  const edge = (await pool.query('SELECT * FROM identity_owned_authority_source_edges WHERE namespace_id=$1 AND source_id=$2', [namespace.namespaceId, retained.lease.id])).rows[0];
  assert.equal(edge.related_id, foreignSource); assert.equal(edge.resolution, 'unresolved'); assert.equal(edge.related_version, null);
  assert.equal((await sourceData(namespace, actor)).sources.some(source => source.id === foreignSource), false);
  assert.equal((await evidence(namespace, actor, recipient.userId)).proposedRoles.includes('license-manager'), false);
});
test('source materialization selects the exact known owner and issuer before locks and never locks foreign users', async () => {
  const actor = await person('license-manager'); const foreign = await person('license-manager'); const namespace = await seal(await candidate(actor, adoptReviewed), actor, undefined, false); const blocker = await pool.connect();
  try {
    await blocker.query('BEGIN'); await blocker.query('SELECT id FROM users WHERE id=$1 FOR UPDATE', [foreign.userId]); const start = Date.now();
    await assert.rejects(bindSources(namespace, foreign), error => error.code === '23503');
    await assert.rejects(database.transaction(async client => { await client.query("SELECT set_config('opendirectory.authority_source_review','explicit-offline-owned-source-review',true)"); await client.query('SELECT identity_authority_bind_sources($1,$2,$3)', [namespace.namespaceId, actor.tenant, 'https://wrong-source-issuer.test']); }), error => error.code === '23503');
    await bindSources(namespace, actor); assert.ok(Date.now() - start < 2000); await assert.rejects(sourceData(namespace, foreign), error => error.code === '23503');
  } finally { await blocker.query('ROLLBACK'); blocker.release(); }
});
test('initial source versions, dispositions, edges and evidence cannot be mutated or extended by unscoped SQL', async () => {
  const actor = await person('license-manager'); const namespace = await seal(await candidate(actor, adoptReviewed), actor);
  for (const statement of ["UPDATE identity_authority_source_sets SET issuer='https://retargeted.test'", "UPDATE identity_owned_authority_source_versions SET disposition='quarantine'", 'DELETE FROM identity_owned_authority_source_versions', 'DELETE FROM identity_authority_source_set_events', "UPDATE identity_authority_source_set_outbox SET status='sent'", 'INSERT INTO identity_owned_authority_source_versions SELECT (jsonb_populate_record(NULL::identity_owned_authority_source_versions,to_jsonb(source)||jsonb_build_object(\'source_version\',2))).* FROM identity_owned_authority_source_versions source'])
    await assert.rejects(pool.query(statement), error => error.code === '42501');
  assert.deepEqual((await evidence(namespace, actor)).proposedRoles, ['license-manager']);
});
for (const retarget of [false, true]) test('changed local source scope cannot admit ' + (retarget ? 'a row into another namespace' : 'an unreviewed second source version'), async () => {
  const actor = await person('license-manager'); const foreign = await person('license-manager'); const other = await seal(await candidate(foreign, adoptReviewed), foreign);
  const namespace = await seal(await candidate(actor, adoptReviewed), actor, undefined, false);
  await assert.rejects(bindSources(namespace, actor, async client => {
    const scope = (await client.query("SELECT current_setting('opendirectory.authority_source_set')::jsonb AS data")).rows[0].data;
    const row = { ...scope.rows.identity_owned_authority_source_versions[0], ...(retarget ? { namespace_id: other.namespaceId, tenant_id: foreign.tenant } : { source_version: 2 }) };
    scope.rows.identity_owned_authority_source_versions.push(row); await client.query("SELECT set_config('opendirectory.authority_source_set',$1,true)", [JSON.stringify(scope)]);
    await client.query('INSERT INTO identity_owned_authority_source_versions SELECT * FROM jsonb_populate_record(NULL::identity_owned_authority_source_versions,$1::jsonb)', [JSON.stringify(row)]);
  }), error => error.code === '42501');
  assert.equal(await sourceCount(), 1); assert.deepEqual((await evidence(other, foreign)).proposedRoles, ['license-manager']);
});
test('deferred source validation rejects changed admission rows even when all retained source rows still look exact', async () => {
  const actor = await person('license-manager'); const namespace = await seal(await candidate(actor, adoptReviewed), actor, undefined, false);
  await assert.rejects(bindSources(namespace, actor, client => client.query("SELECT set_config('opendirectory.authority_source_set',jsonb_set(current_setting('opendirectory.authority_source_set')::jsonb,'{rows,identity_owned_authority_source_edges}','[{}]')::text,true)")), error => error.code === '42501');
  assert.equal(await sourceCount(), 0);
});
test('missing exact source row, edge, deferred, live-effect and truncate guards prevent materialization atomically', async () => {
  const actor = await person('license-manager'); const namespace = await seal(await candidate(actor, adoptReviewed), actor, undefined, false);
  for (const [table, trigger] of [['identity_authority_source_sets', 'identity_authority_source_set_guard'], ['identity_owned_authority_source_versions', 'identity_authority_source_set_guard'], ['identity_owned_authority_source_edges', 'identity_authority_source_set_guard'], ['identity_authority_source_sets', 'identity_authority_source_set_commit'], ['users', 'aaa_identity_authority_source_set_no_effects'], ['groups', 'aaa_identity_authority_source_set_no_truncate']]) {
    await pool.query('ALTER TABLE ' + table + ' DISABLE TRIGGER ' + trigger);
    try { await assert.rejects(bindSources(namespace, actor), error => error.code === '42501'); } finally { await pool.query('ALTER TABLE ' + table + ' ENABLE TRIGGER ' + trigger); }
  }
  assert.equal(await sourceCount(), 0);
});
for (const table of ['identity_authority_source_set_events', 'identity_authority_source_set_outbox']) test('a missing receiving row in ' + table + ' rolls back all materialized sources', async () => {
  const actor = await person('license-manager'); const namespace = await seal(await candidate(actor, adoptReviewed), actor, undefined, false);
  await pool.query('CREATE FUNCTION omit_owned_source_evidence() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL;END;$$;CREATE TRIGGER zzz_omit_owned_source_evidence BEFORE INSERT ON ' + table + ' FOR EACH ROW EXECUTE FUNCTION omit_owned_source_evidence()');
  try { await assert.rejects(bindSources(namespace, actor), error => ['42501', '23503'].includes(error.code)); }
  finally { await pool.query('DROP TRIGGER zzz_omit_owned_source_evidence ON ' + table + ';DROP FUNCTION omit_owned_source_evidence()'); }
  assert.equal(await sourceCount(), 0); assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_owned_authority_source_versions')).rows[0].count, 0);
});
test('a late source row rewrite cannot survive the exact retained-content receipt', async () => {
  const actor = await person('license-manager'); const namespace = await seal(await candidate(actor, adoptReviewed), actor, undefined, false);
  await pool.query("CREATE FUNCTION alter_owned_source_state() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN NEW.source_state=jsonb_set(NEW.source_state,'{reason}','\"Unrequested rewritten historical reason\"');RETURN NEW;END;$$;CREATE TRIGGER zzz_alter_owned_source_state BEFORE INSERT ON identity_owned_authority_source_versions FOR EACH ROW EXECUTE FUNCTION alter_owned_source_state()");
  try { await assert.rejects(bindSources(namespace, actor), error => error.code === '42501'); }
  finally { await pool.query('DROP TRIGGER zzz_alter_owned_source_state ON identity_owned_authority_source_versions;DROP FUNCTION alter_owned_source_state()'); }
  assert.equal(await sourceCount(), 0);
});
test('clearing source scope cannot hide late live writes, truncation or absent deferred admission', async () => {
  const actor = await person('license-manager'); const foreign = await person('user'); const namespace = await seal(await candidate(actor, adoptReviewed), actor, undefined, false);
  for (const effect of [client => client.query("UPDATE users SET title='Unrequested source materialization effect' WHERE id=$1", [foreign.userId]), client => client.query('TRUNCATE group_members'), async () => {}]) {
    await assert.rejects(bindSources(namespace, actor, async client => { await client.query("SELECT set_config('opendirectory.authority_source_set','',true)"); await effect(client); }), error => error.code === '42501');
  }
  assert.equal(await sourceCount(), 0); assert.equal((await pool.query('SELECT title FROM users WHERE id=$1', [foreign.userId])).rows[0].title, null);
});
test('earlier canonical writes and uncommitted policy seals cannot ride a source materialization transaction', async () => {
  const actor = await person('license-manager'); const staged = await candidate(actor, adoptReviewed); const namespace = await seal(staged, actor, undefined, false);
  await assert.rejects(database.transaction(async client => { await client.query("UPDATE users SET title='Unrequested preceding source effect' WHERE id=$1", [actor.userId]); await client.query("SELECT set_config('opendirectory.authority_source_review','explicit-offline-owned-source-review',true)"); await client.query('SELECT identity_authority_bind_sources($1,$2,$3)', [namespace.namespaceId, actor.tenant, issuer]); }), error => error.code === '42501' && error.message.includes('Fresh transaction'));
  const current = await candidate(actor, body => { body.reason = 'Distinct reviewed policy namespace for a same-transaction rejection'; });
  await assert.rejects(seal(current, actor, async (client, uncommitted) => { await client.query("SELECT set_config('opendirectory.authority_source_review','explicit-offline-owned-source-review',true),set_config('opendirectory.authority_seal','',true)"); await client.query('SELECT identity_authority_bind_sources($1,$2,$3)', [uncommitted.namespaceId, actor.tenant, issuer]); }), error => error.code === '42501');
  assert.equal(await sourceCount(), 0); assert.equal((await pool.query('SELECT title FROM users WHERE id=$1', [actor.userId])).rows[0].title, null);
});
test('a post-seal authority change cannot silently rebase the reviewed source set', async () => {
  const actor = await person('license-manager'); const namespace = await seal(await candidate(actor, adoptReviewed), actor, undefined, false);
  await pool.query('UPDATE users SET authorization_revision=authorization_revision+1 WHERE id=$1', [actor.userId]);
  await assert.rejects(bindSources(namespace, actor), error => error.code === '42501'); assert.equal(await sourceCount(), 0);
});
test('physical original expiry after source DML rolls back every typed base and pending receipt', async () => {
  const actor = await person('admin'); const recipient = await person('user', actor.tenant); await grant(actor, recipient, 'license-manager', 2);
  const namespace = await seal(await candidate(actor, adoptReviewed), actor, undefined, false);
  await assert.rejects(bindSources(namespace, actor, client => client.query('SELECT pg_sleep(2.1)')), error => error.code === '42501'); assert.equal(await sourceCount(), 0);
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_authority_source_set_events')).rows[0].count, 0);
});
test('owned source inspection refuses uncommitted materialization and detects lost or altered retained evidence', async () => {
  const actor = await person('license-manager'); const namespace = await seal(await candidate(actor, adoptReviewed), actor, undefined, false);
  await assert.rejects(bindSources(namespace, actor, client => sourceData(namespace, actor, client)), error => error.code === '42501' && error.message === 'Committed owned source set required');
  await bindSources(namespace, actor); await pool.query('ALTER TABLE identity_authority_source_set_outbox RENAME TO withheld_typed_source_outbox');
  try { await assert.rejects(evidence(namespace, actor)); } finally { await pool.query('ALTER TABLE withheld_typed_source_outbox RENAME TO identity_authority_source_set_outbox'); }
  await pool.query('ALTER TABLE identity_authority_source_set_events DISABLE TRIGGER identity_authority_source_set_guard');
  try { await pool.query("UPDATE identity_authority_source_set_events SET details='{}' WHERE id=$1", [namespace.namespaceId]); } finally { await pool.query('ALTER TABLE identity_authority_source_set_events ENABLE TRIGGER identity_authority_source_set_guard'); }
  await assert.rejects(evidence(namespace, actor), error => error.code === '42501');
});
test('a granted definer cannot launder a real limited login or SET ROLE into source materialization or inspection', async () => {
  const actor = await person('license-manager'); const namespace = await seal(await candidate(actor, adoptReviewed), actor, undefined, false); const role = 'source_base_limited_' + randomUUID().replaceAll('-', ''); let limited;
  await administration.query(`CREATE ROLE ${role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS`);
  try {
    await pool.query(`GRANT USAGE ON SCHEMA ${schema} TO ${role};GRANT EXECUTE ON FUNCTION identity_authority_bind_sources(uuid,uuid,text),identity_authority_owned_source_data(uuid,uuid,text),identity_authority_source_set_rows(uuid) TO ${role}`);
    const address = new URL(process.env.IDENTITY_TEST_DATABASE_URL); address.username = role; limited = new Pool({ connectionString: address.toString(), max: 1, options: `-c search_path=${schema},public` });
    for (const assumed of [false, true]) for (const operation of ['materialize', 'inspect', 'rows']) {
      const client = await (assumed ? pool : limited).connect();
      try { await client.query('BEGIN'); if (assumed) await client.query('SET LOCAL ROLE ' + role); await client.query("SELECT set_config('opendirectory.authority_source_review','explicit-offline-owned-source-review',true)");
        const query = operation === 'rows' ? client.query('SELECT identity_authority_source_set_rows($1)', [namespace.namespaceId]) : operation === 'inspect' ? sourceData(namespace, actor, client) : client.query('SELECT identity_authority_bind_sources($1,$2,$3)', [namespace.namespaceId, actor.tenant, issuer]);
        await assert.rejects(query, error => error.code === '42501' && error.message === 'Actual database owner required for offline authority review');
      } finally { await client.query('ROLLBACK'); client.release(); }
    }
  } finally { await limited?.end(); await pool.query('DROP OWNED BY ' + role); await administration.query('DROP ROLE ' + role); }
});
test('source-base migration replay and real time zones preserve versions, content and evidence without repeating materialization', async () => {
  const actor = await person('license-manager'); const namespace = await seal(await candidate(actor, adoptReviewed), actor, undefined, false);
  await database.transaction(async client => { await client.query("SET LOCAL timezone='Europe/Zurich';SELECT set_config('opendirectory.authority_source_review','explicit-offline-owned-source-review',true)"); await client.query('SELECT identity_authority_bind_sources($1,$2,$3)', [namespace.namespaceId, actor.tenant, issuer]); });
  const before = await sourceData(namespace, actor); const resolved = await evidence(namespace, actor);
  await pool.query(fs.readFileSync(path.join(migrations, '036_owned_authority_source_bindings.sql'), 'utf8'));
  const elsewhere = await database.transaction(async client => { await client.query("SET LOCAL timezone='Pacific/Honolulu'"); return sourceData(namespace, actor, client); }, { readOnly: true });
  assert.deepEqual(elsewhere, before); assert.deepEqual(await evidence(namespace, actor), resolved); await assert.rejects(bindSources(namespace, actor), error => error.code === '23505'); assert.equal(await sourceCount(), 1);
});
