'use strict';

const { test, before, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { Pool } = require('pg');
const { AuthorizationState } = require('../AuthorizationState');
const { DirectoryRoles } = require('../DirectoryRoles');
const { PrivilegedActivation } = require('../PrivilegedActivation');
const { resolveOwnedAuthorityPlan } = require('../OwnedAuthorityPlan');
const { ROLES, MFA_LOCKED_ROLES, PROTECTED } = require('../../../../../packages/directory-role-contract');
const { provisionTenant, adoptTenant, enableTenant } = require('../../../../../scripts/lib/tenant-ownership-fixture.cjs');
const { bootstrapRole } = require('../../scripts/bootstrap-role');

const schema = 'authority_candidates_' + randomUUID().replaceAll('-', '');
const administration = new Pool({ connectionString: process.env.IDENTITY_TEST_DATABASE_URL, max: 1 });
const issuer = 'https://authority-candidate.test';
const migrations = path.join(__dirname, '../../migrations');
let pool; let database;
before(async () => {
  await administration.query('CREATE SCHEMA ' + schema);
  pool = new Pool({ connectionString: process.env.IDENTITY_TEST_DATABASE_URL, max: 8, options: `-c search_path=${schema},public` });
  database = { isAvailable: () => true, query: (...args) => pool.query(...args), getClient: () => pool.connect(),
    transaction: async (operation, options = {}) => {
      const client = await pool.connect();
      try {
        await client.query(options.readOnly ? 'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY' : 'BEGIN');
        await client.query("SET LOCAL lock_timeout='5s';SET LOCAL statement_timeout='15s'");
        if (options.actor) await client.query("SELECT set_config('opendirectory.actor',$1,true)", [options.actor]);
        const result = await operation(client); await client.query('COMMIT'); return result;
      } catch (error) { await client.query('ROLLBACK'); throw error; } finally { client.release(); }
    } };
  for (const file of fs.readdirSync(migrations).filter(file => file.endsWith('.sql')).sort()) await pool.query(fs.readFileSync(path.join(migrations, file), 'utf8'));
});
beforeEach(async () => { await pool.query('TRUNCATE identity_tenants,users,groups,ous,identity_role_review_policies,identity_role_assignments,identity_pim_eligibilities CASCADE'); });
after(async () => { await pool.end(); await administration.query('DROP SCHEMA ' + schema + ' CASCADE'); await administration.end(); });

async function person(role = 'user', tenant) {
  tenant = tenant || await provisionTenant(database, schema, { enabled: true });
  const userId = randomUUID(); const subject = 'candidate-' + randomUUID();
  await pool.query('INSERT INTO users(id,username,email,display_name) VALUES($1,$2,$3,$4)', [userId, subject, 'private-' + subject + '@test.invalid', 'Private personal label']);
  await pool.query('INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES($1,$2,$3)', [issuer, subject, userId]);
  await adoptTenant(database, schema, tenant, [{ kind: 'user', resourceId: userId }]);
  await bootstrapRole(database, { userId, role, duration: 3600, reason: 'Explicit reviewed finite source for isolated candidate tests' });
  const state = await new AuthorizationState(database).state(issuer, subject);
  return { tenant, userId, user: { iss: issuer, sub: subject, actor_type: 'user', roles: state.roles, identity_authorization: state.context, jti: randomUUID(), exp: Math.floor(Date.now() / 1000) + 300 } };
}
async function inventory(owner) {
  const data = (await pool.query('SELECT identity_authority_inventory($1,$2) AS data', [owner, issuer])).rows[0].data;
  const digest = (await pool.query('SELECT identity_authority_hash($1::jsonb) AS digest', [JSON.stringify(data)])).rows[0].digest;
  return { data, digest };
}
async function manifest(actor, { adopt = false } = {}) {
  const current = await inventory(actor.tenant);
  return { schemaVersion: 1, tenantId: actor.tenant, expectedTenantVersion: current.data.tenant.version, expectedTenantGeneration: current.data.tenant.generation,
    issuer, reviewAnchorUserId: actor.userId, inventorySha256: current.digest,
    policies: ROLES.map(role => ({ role, authentication: { required: true, maxAgeSeconds: 300 }, activation: { required: false, maxDurationSeconds: 28800, reviewerUserIds: [] }, review: null })),
    sources: current.data.sources.map(source => ({ kind: source.kind, id: source.id, disposition: adopt ? 'adopt' : 'quarantine', ...(adopt && source.origin === 'offline-review-required' ? { acceptOfflineOrigin: true } : {}) })),
    reason: 'Explicit offline draft review without granting or activating authority' };
}
async function stage(body, afterStage) {
  return database.transaction(async client => {
    await client.query("SELECT set_config('opendirectory.authority_review','explicit-offline-authority-review',true)");
    const result = (await client.query('SELECT identity_authority_stage($1::jsonb) AS data', [JSON.stringify(body)])).rows[0].data;
    if (afterStage) await afterStage(client, result);
    return result;
  });
}
async function countCandidates() { return (await pool.query('SELECT count(*)::int AS count FROM identity_authority_candidates')).rows[0].count; }
async function sourceSnapshot(candidate, actor, client = pool) {
  return (await client.query('SELECT identity_authority_candidate_snapshot($1,$2,$3) AS snapshot', [candidate.id, actor.tenant, issuer])).rows[0].snapshot;
}
async function importLegacyAuthority(relation, actor, operation) {
  await pool.query('ALTER TABLE ' + relation + ' DISABLE TRIGGER aaa_identity_authority_target_tenant');
  try { return await database.transaction(operation, { actor: JSON.stringify({ issuer, subject: actor.user.sub, userId: actor.userId }) }); }
  finally { await pool.query('ALTER TABLE ' + relation + ' ENABLE TRIGGER aaa_identity_authority_target_tenant'); }
}
async function importForeignGrant(actor, recipient, reason) {
  return importLegacyAuthority('identity_role_assignments', actor, async client => (await client.query("INSERT INTO identity_role_assignments(user_id,role,reason,expires_at) VALUES($1,'license-manager',$2,clock_timestamp()+interval '300 seconds') RETURNING id", [recipient.userId, reason])).rows[0]);
}

test('the SQL migration catalog exactly matches the canonical catalog and fixed MFA duties', async () => {
  assert.deepEqual((await pool.query('SELECT identity_authority_catalog() AS data')).rows[0].data,
    { roles: [...ROLES].sort(), lockedMfaRoles: [...MFA_LOCKED_ROLES].sort(), protectedRoles: [...PROTECTED].sort() });
});
test('a complete explicit reviewed proposal creates only a retained draft, mandatory event and pending outbox', async () => {
  const actor = await person('admin'); const before = await new AuthorizationState(database).state(issuer, actor.user.sub); const body = await manifest(actor, { adopt: true }); const result = await stage(body);
  assert.equal(result.state, 'draft'); assert.equal(result.canAuthorize, false); assert.equal(result.adoptionIntentCount, 1); assert.equal(result.policyCount, ROLES.length);
  const stored = (await pool.query('SELECT candidate.*,event.actor,outbox.status FROM identity_authority_candidates candidate JOIN identity_authority_candidate_events event USING(id) JOIN identity_authority_candidate_outbox outbox USING(id) WHERE id=$1', [result.id])).rows[0];
  assert.equal(stored.tenant_id, actor.tenant); assert.equal(stored.status, 'pending'); assert.equal(stored.actor.kind, 'offline-authority-stage'); assert.equal(stored.actor.reviewAnchorUserId, actor.userId);
  assert.equal(stored.valid_until > new Date(), true); assert.equal(stored.valid_until - stored.created_at <= 900000, true);
  assert.deepEqual(await new AuthorizationState(database).state(issuer, actor.user.sub), before);
  assert.equal(JSON.stringify(stored.inventory).includes('private-'), false); assert.equal(JSON.stringify(stored.inventory).includes('Private personal label'), false); assert.equal(JSON.stringify(stored.inventory).includes('Explicit reviewed finite'), false);
});
test('a foreign legacy grant and PIM eligibility can only be explicitly quarantined, not positively adopted', async () => {
  const operator = await person('admin'); const foreign = await person();
  await importForeignGrant(operator, foreign, 'Deliberately imported pre-fence cross-owner grant for migration');
  await importLegacyAuthority('identity_pim_eligibilities', operator, client => client.query("INSERT INTO identity_pim_eligibilities(user_id,role,reason,max_duration_seconds,expires_at) VALUES($1,'license-manager','Deliberately imported pre-fence cross-owner eligibility',300,clock_timestamp()+interval '1 hour')", [foreign.userId]));
  const current = await inventory(foreign.tenant); const contaminated = current.data.sources.filter(source => source.role === 'license-manager'); assert.equal(contaminated.length, 2); assert.ok(contaminated.every(source => source.origin === 'foreign'));
  const rejected = await manifest(foreign, { adopt: true }); await assert.rejects(stage(rejected), error => error.code === '23514'); assert.equal(await countCandidates(), 0);
  const quarantined = await stage(await manifest(foreign)); assert.equal(quarantined.adoptionIntentCount, 0); assert.equal(quarantined.quarantineIntentCount, 3);
});
test('unresolved raw actor history and an unacknowledged offline source cannot be treated as positive provenance', async () => {
  const actor = await person(); await pool.query("INSERT INTO identity_role_assignments(user_id,role,reason,expires_at) VALUES($1,'license-reader','Unresolved historical raw source for migration',clock_timestamp()+interval '5 minutes')", [actor.userId]);
  const unknown = await manifest(actor, { adopt: true }); await assert.rejects(stage(unknown), error => error.code === '23514');
  const offline = await manifest(actor); offline.sources = offline.sources.map(source => ({ kind: source.kind, id: source.id, disposition: 'adopt' })); await assert.rejects(stage(offline), error => error.code === '23514'); assert.equal(await countCandidates(), 0);
});
test('missing, duplicate, foreign or invented source classifications fail without partial staging', async () => {
  const actor = await person(); const foreign = await person(); const original = await manifest(actor); const foreignSource = (await inventory(foreign.tenant)).data.sources[0];
  for (const sources of [[], [original.sources[0], original.sources[0]], [{ ...original.sources[0], id: randomUUID() }], [{ ...original.sources[0], id: foreignSource.id }]]) await assert.rejects(stage({ ...original, sources }), error => error.code === '23514');
  assert.equal(await countCandidates(), 0);
});
test('complete typed role proposals cannot omit, duplicate, invent or weaken policy and fixed MFA', async () => {
  const actor = await person('admin'); const original = await manifest(actor);
  for (const transform of [body => body.policies.pop(), body => { body.policies[0] = body.policies[1]; }, body => { body.policies[0].role = 'invented-owner'; },
    body => { body.policies.find(policy => policy.role === 'group-reviewer').authentication.required = false; }, body => { body.policies[0].authentication.maxAgeSeconds = '300'; },
    body => { body.policies[0].activation.maxDurationSeconds = 30000; }, body => { body.policies[0].unknown = true; }]) {
    const changed = structuredClone(original); transform(changed); await assert.rejects(stage(changed));
  }
  assert.equal(await countCandidates(), 0);
});
test('referenced policy reviewers and the review anchor must be owned canonical enabled users', async () => {
  const actor = await person('admin'); const foreign = await person('pim-approver'); const disabled = await person('pim-approver', actor.tenant); await pool.query('UPDATE users SET enabled=false WHERE id=$1', [disabled.userId]); const original = await manifest(actor);
  for (const userId of [foreign.userId, disabled.userId, actor.userId, randomUUID()]) { const body = structuredClone(original); const profile = body.policies.find(policy => policy.role === 'admin'); profile.activation.required = true; profile.activation.reviewerUserIds = [userId]; await assert.rejects(stage(body), error => error.code === '23514'); }
  await assert.rejects(stage({ ...original, reviewAnchorUserId: foreign.userId }), error => error.code === '23514'); assert.equal(await countCandidates(), 0);
});
test('changed tenant versions, exact inventory content and issuer cannot be silently rebased', async () => {
  const actor = await person(); const body = await manifest(actor); await pool.query("UPDATE users SET enabled=false WHERE id=$1", [actor.userId]); await assert.rejects(stage(body), error => error.code === '23514'); await pool.query('UPDATE users SET enabled=true WHERE id=$1', [actor.userId]);
  const current = await manifest(actor); await enableTenant(database, schema, actor.tenant, false); await enableTenant(database, schema, actor.tenant, true); await assert.rejects(stage(current), error => error.code === '23514');
  await assert.rejects(stage({ ...await manifest(actor), issuer: 'https://other-authority.test' }), error => error.code === '23514'); assert.equal(await countCandidates(), 0);
});
test('staged reviewed input is immutable and cannot be flipped into an active namespace or replayed', async () => {
  const actor = await person(); const body = await manifest(actor); await stage(body);
  for (const sql of ["UPDATE identity_authority_candidates SET state='active'", "UPDATE identity_authority_candidates SET valid_until=valid_until+interval '1 hour'", 'DELETE FROM identity_authority_candidates', 'DELETE FROM identity_authority_candidate_events', "UPDATE identity_authority_candidate_outbox SET status='delivered'"]) await assert.rejects(pool.query(sql));
  await assert.rejects(stage(body), error => error.code === '23505'); assert.equal(await countCandidates(), 1);
});
test('an unrelated live write cannot ride staging even after the caller clears and restores its local scope', async () => {
  const actor = await person(); const foreign = await person(); const body = await manifest(actor);
  await assert.rejects(stage(body, async client => { const scope = (await client.query("SELECT current_setting('opendirectory.authority_stage') AS scope")).rows[0].scope; await client.query("SELECT set_config('opendirectory.authority_stage','',true)"); await client.query("UPDATE users SET title='Unrequested live change' WHERE id=$1", [foreign.userId]); await client.query("SELECT set_config('opendirectory.authority_stage',$1,true)", [scope]); }), error => error.code === '42501');
  assert.equal((await pool.query('SELECT title FROM users WHERE id=$1', [foreign.userId])).rows[0].title, null); assert.equal(await countCandidates(), 0);
});
test('cleared scope, missing receiving guards or missing evidence cannot become a confirmed draft', async () => {
  const actor = await person(); const body = await manifest(actor);
  await assert.rejects(stage(body, client => client.query("SELECT set_config('opendirectory.authority_stage','',true)")), error => error.code === '42501');
  for (const trigger of ['identity_authority_candidate_guard', 'identity_authority_candidate_commit']) { await pool.query('ALTER TABLE identity_authority_candidates DISABLE TRIGGER ' + trigger); try { await assert.rejects(stage(body), error => error.code === '42501'); } finally { await pool.query('ALTER TABLE identity_authority_candidates ENABLE TRIGGER ' + trigger); } }
  await pool.query('ALTER TABLE identity_authority_candidate_outbox RENAME TO withheld_authority_outbox'); try { await assert.rejects(stage(body)); } finally { await pool.query('ALTER TABLE withheld_authority_outbox RENAME TO identity_authority_candidate_outbox'); } assert.equal(await countCandidates(), 0);
});
test('a retained source expiry bounds its inactive candidate without extending or replacing the original grant', async () => {
  const actor = await person(); await pool.query("UPDATE users SET authorization_revision=authorization_revision+1 WHERE id=$1", [actor.userId]);
  const helper = await person('admin', actor.tenant); const grant = await new DirectoryRoles(database, { revalidate: async () => {} }).grant(actor.userId, { role: 'license-reader', durationSeconds: 60, reason: 'Actually bounded source lifetime retained during authority staging' }, helper.user);
  const body = await manifest(actor); body.sources.find(source => source.id === grant.id).disposition = 'adopt'; const result = await stage(body); const source = (await pool.query('SELECT expires_at FROM identity_role_assignments WHERE id=$1', [grant.id])).rows[0]; assert.equal(Date.parse(result.validUntil), source.expires_at.getTime());
});
test('migration replay preserves the exact draft, snapshots and pending evidence without touching live source', async () => {
  const actor = await person(); const result = await stage(await manifest(actor)); const before = (await pool.query('SELECT * FROM identity_authority_candidates WHERE id=$1', [result.id])).rows;
  await pool.query(fs.readFileSync(path.join(migrations, '030_authority_migration_candidates.sql'), 'utf8')); assert.deepEqual((await pool.query('SELECT * FROM identity_authority_candidates WHERE id=$1', [result.id])).rows, before);
});

test('pending PIM approvals cannot be carried into a new authority namespace as activatable authority', async () => {
  const operator = await person('admin'); const recipient = await person('user', operator.tenant); const store = new PrivilegedActivation(database, { revalidate: async () => {} });
  const eligibility = await store.grantEligibility({ userId: recipient.userId, role: 'license-manager', maxDurationSeconds: 300, validForSeconds: 3600, reason: 'Owned eligibility retained for migration of a pending source' }, operator.user);
  const source = await new AuthorizationState(database).state(issuer, recipient.user.sub); recipient.user.identity_authorization = source.context;
  const request = await store.request({ id: randomUUID(), eligibilityId: eligibility.id, durationSeconds: 300, reason: 'Pending global policy approval must not become a new positive source' }, recipient.user);
  const body = await manifest(operator, { adopt: true }); assert.equal((await inventory(operator.tenant)).data.sources.find(row => row.id === request.id).live, false);
  await assert.rejects(stage(body), error => error.code === '23514'); body.sources.find(row => row.id === request.id).disposition = 'quarantine'; await stage(body);
  assert.deepEqual((await new AuthorizationState(database).state(issuer, recipient.user.sub)).roles, ['user']);
});

test('adopted review components preserve actual source and deadline instead of resetting capture on staging', async () => {
  const operator = await person('admin'); const recipient = await person('user', operator.tenant); const voter = await person('access-reviewer', operator.tenant);
  await new DirectoryRoles(database, { revalidate: async () => {} }).grant(recipient.userId, { role: 'license-manager', durationSeconds: 3600, reason: 'Actual owned role source captured for migration review' }, operator.user);
  await database.transaction(async client => {
    await client.query("SELECT set_config('opendirectory.review_reason','Explicit owned legacy recurring policy fixture',true)");
    await client.query('INSERT INTO identity_role_review_policies(role,interval_seconds,window_seconds,reviewer_user_ids) VALUES($1,3600,300,$2)', ['license-manager', [voter.userId]]);
  }, { actor: JSON.stringify({ issuer, subject: operator.user.sub, userId: operator.userId }) });
  const original = (await pool.query('SELECT * FROM identity_role_review_leases')).rows; assert.equal(original.length, 1);
  const body = await manifest(operator, { adopt: true }); body.policies.find(profile => profile.role === 'license-manager').review = { intervalSeconds: 3600, windowSeconds: 300, reviewerUserIds: [voter.userId] };
  const broken = structuredClone(body); broken.sources.find(source => source.kind === 'review').disposition = 'quarantine'; await assert.rejects(stage(broken), error => error.code === '23514');
  const result = await stage(body); assert.equal(Date.parse(result.validUntil), original[0].deadline_at.getTime()); assert.deepEqual((await pool.query('SELECT * FROM identity_role_review_leases')).rows, original);
});

test('a legacy review configured with a foreign voter cannot become an adopted owned authority component', async () => {
  const operator = await person('admin'); const recipient = await person('user', operator.tenant); const foreign = await person('access-reviewer');
  await new DirectoryRoles(database, { revalidate: async () => {} }).grant(recipient.userId, { role: 'license-manager', durationSeconds: 3600, reason: 'Owned source with deliberately foreign legacy review configuration' }, operator.user);
  await importLegacyAuthority('identity_role_review_leases', operator, async client => { await client.query("SELECT set_config('opendirectory.review_reason','Known imported legacy foreign reviewer requires quarantine',true)"); await client.query('INSERT INTO identity_role_review_policies(role,interval_seconds,window_seconds,reviewer_user_ids) VALUES($1,3600,300,$2)', ['license-manager', [foreign.userId]]); });
  const owned = await person('access-reviewer', operator.tenant); const body = await manifest(operator, { adopt: true }); body.policies.find(profile => profile.role === 'license-manager').review = { intervalSeconds: 3600, windowSeconds: 300, reviewerUserIds: [owned.userId] };
  assert.equal((await inventory(operator.tenant)).data.sources.find(source => source.kind === 'review').origin, 'foreign'); await assert.rejects(stage(body), error => error.code === '23514'); assert.equal(await countCandidates(), 0);
});

test('physical source expiry after staging DML invalidates the deferred draft receipt', async () => {
  const operator = await person('admin'); const recipient = await person('user', operator.tenant); let identifier;
  await database.transaction(async client => { identifier = (await client.query("INSERT INTO identity_role_assignments(user_id,role,reason,expires_at) VALUES($1,'license-reader','Actual two-second retained legacy source deadline',clock_timestamp()+interval '2 seconds') RETURNING id", [recipient.userId])).rows[0].id; }, { actor: JSON.stringify({ issuer, subject: operator.user.sub, userId: operator.userId }) });
  const body = await manifest(operator); body.sources.find(source => source.id === identifier).disposition = 'adopt'; await assert.rejects(stage(body, client => client.query('SELECT pg_sleep(2.1)')), error => error.code === '42501'); assert.equal(await countCandidates(), 0);
});

test('late receiving triggers cannot extend candidate lifetime or rewrite original review evidence', async () => {
  const actor = await person(); const body = await manifest(actor);
  for (const target of ['candidate', 'event']) {
    const relation = target === 'candidate' ? 'identity_authority_candidates' : 'identity_authority_candidate_events'; const alteration = target === 'candidate' ? "NEW.valid_until=NEW.valid_until+interval '1 hour';" : "NEW.actor='{}';";
    await pool.query(`CREATE FUNCTION unconfirmed_authority_content() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN ${alteration} RETURN NEW;END;$$;CREATE TRIGGER zzz_unconfirmed_authority_content BEFORE INSERT ON ${relation} FOR EACH ROW EXECUTE FUNCTION unconfirmed_authority_content()`);
    try { await assert.rejects(stage(body), error => error.code === '42501'); } finally { await pool.query(`DROP TRIGGER zzz_unconfirmed_authority_content ON ${relation};DROP FUNCTION unconfirmed_authority_content()`); }
  }
  assert.equal(await countCandidates(), 0);
});

test('a missing legacy no-effects guard is a receiver failure, not permission to stage', async () => {
  const actor = await person(); const body = await manifest(actor); await pool.query('ALTER TABLE users DISABLE TRIGGER aaa_identity_authority_stage_no_effects');
  try { await assert.rejects(stage(body), error => error.code === '42501'); } finally { await pool.query('ALTER TABLE users ENABLE TRIGGER aaa_identity_authority_stage_no_effects'); }
  assert.equal(await countCandidates(), 0);
});

test('foreign reviewer rows are rejected without waiting on their independently held user lock', async () => {
  const actor = await person('admin'); const foreign = await person('pim-approver'); const body = await manifest(actor); const profile = body.policies.find(policy => policy.role === 'admin'); profile.activation.required = true; profile.activation.reviewerUserIds = [foreign.userId]; const blocker = await pool.connect();
  try { await blocker.query('BEGIN'); await blocker.query('SELECT id FROM users WHERE id=$1 FOR UPDATE', [foreign.userId]); const started = Date.now(); await assert.rejects(stage(body), error => error.code === '23514'); assert.ok(Date.now() - started < 2000); } finally { await blocker.query('ROLLBACK'); blocker.release(); }
});

test('observed owned-user lock waits reject a source changed after the reviewed inventory', async () => {
  const actor = await person(); const body = await manifest(actor); const blocker = await pool.connect(); let pending;
  try {
    await blocker.query('BEGIN'); const backend = (await blocker.query('SELECT pg_backend_pid() AS id')).rows[0].id; await blocker.query('SELECT id FROM users WHERE id=$1 FOR UPDATE', [actor.userId]); pending = stage(body); pending.catch(() => {}); let waiting = false;
    for (let attempt = 0; attempt < 200; attempt++) { waiting = (await pool.query("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(pid))) AS waiting", [backend])).rows[0].waiting; if (waiting) break; await new Promise(resolve => setTimeout(resolve, 5)); }
    assert.equal(waiting, true); await blocker.query('UPDATE users SET enabled=false WHERE id=$1', [actor.userId]); await blocker.query('COMMIT'); await assert.rejects(pending, error => error.code === '23514');
  } finally { await blocker.query('ROLLBACK'); blocker.release(); if (pending) await pending.catch(() => {}); }
  assert.equal(await countCandidates(), 0);
});

test('limited real SQL logins and assumed roles cannot launder offline review through definer functions', async () => {
  const actor = await person(); const body = await manifest(actor); const role = 'authority_limited_' + randomUUID().replaceAll('-', ''); let limited;
  await administration.query(`CREATE ROLE ${role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS`);
  try {
    await pool.query(`GRANT USAGE ON SCHEMA ${schema} TO ${role};GRANT EXECUTE ON FUNCTION identity_authority_inventory(uuid,text),identity_authority_stage(jsonb) TO ${role}`);
    const address = new URL(process.env.IDENTITY_TEST_DATABASE_URL); address.username = role; limited = new Pool({ connectionString: address.toString(), max: 1, options: `-c search_path=${schema},public` });
    for (const assumed of [false, true]) { const client = await (assumed ? pool : limited).connect(); try { await client.query('BEGIN'); if (assumed) await client.query('SET LOCAL ROLE ' + role); await client.query("SELECT set_config('opendirectory.authority_review','explicit-offline-authority-review',true)"); await assert.rejects(client.query('SELECT identity_authority_stage($1::jsonb)', [JSON.stringify(body)]), error => error.code === '42501' && error.message === 'Actual database owner required for offline authority review'); } finally { await client.query('ROLLBACK'); client.release(); } }
  } finally { await limited?.end(); await pool.query('DROP OWNED BY ' + role); await administration.query('DROP ROLE ' + role); }
  assert.equal(await countCandidates(), 0);
});

test('inventory refuses an oversized complete source graph instead of staging a truncated namespace', async () => {
  const actor = await person(); await pool.query("INSERT INTO identity_role_assignments(user_id,role,reason,expires_at) SELECT $1,'license-reader','Explicit oversized retained history for staging boundary',clock_timestamp()+interval '5 minutes' FROM generate_series(1,1000)", [actor.userId]);
  await assert.rejects(inventory(actor.tenant), error => error.code === '54000'); assert.equal(await countCandidates(), 0);
});

test('generations above JavaScript safe integer precision retain exact strings through manifest confirmation', async () => {
  const actor = await person(); await pool.query("SELECT setval('identity_tenant_generation_seq',9007199254740993,true)"); await enableTenant(database, schema, actor.tenant, false); await enableTenant(database, schema, actor.tenant, true); const body = await manifest(actor);
  assert.ok(BigInt(body.expectedTenantGeneration) > BigInt(Number.MAX_SAFE_INTEGER)); const result = await stage(body); const stored = (await pool.query('SELECT tenant_generation::text AS generation FROM identity_authority_candidates WHERE id=$1', [result.id])).rows[0]; assert.equal(stored.generation, body.expectedTenantGeneration);
  assert.deepEqual((await pool.query("SELECT identity_authority_state('{\"version\":9007199254740993,\"cycle\":9007199254740994,\"policy_version\":9007199254740995}'::jsonb) AS state")).rows[0].state, { version: '9007199254740993', cycle: '9007199254740994', policy_version: '9007199254740995' });
});

test('the real offline CLI commits evidence before emitting a non-authorizing draft and has no application-database fallback', async () => {
  const actor = await person(); const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'od-authority-review-')); const script = path.join(__dirname, '../../scripts/authority-review.js'); const environment = { ...process.env, IDENTITY_AUTHORITY_REVIEW_DATABASE_URL: process.env.IDENTITY_TEST_DATABASE_URL, IDENTITY_AUTHORITY_REVIEW_SCHEMA: schema };
  try {
    const read = JSON.parse(execFileSync(process.execPath, [script, 'inventory', actor.tenant, issuer], { env: environment, encoding: 'utf8' })); assert.equal(read.canAuthorize, false); assert.equal(read.inventorySha256, (await inventory(actor.tenant)).digest);
    const filename = path.join(directory, 'manifest.json'); fs.writeFileSync(filename, JSON.stringify(await manifest(actor))); const result = JSON.parse(execFileSync(process.execPath, [script, 'stage', filename], { env: environment, encoding: 'utf8' })); assert.equal(result.state, 'draft'); assert.equal(result.canAuthorize, false);
    assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_authority_candidate_outbox WHERE id=$1', [result.id])).rows[0].count, 1);
    let rejected; try { execFileSync(process.execPath, [script, 'stage', filename], { env: { ...environment, IDENTITY_AUTHORITY_REVIEW_DATABASE_URL: '', DATABASE_URL: process.env.IDENTITY_TEST_DATABASE_URL }, stdio: 'pipe' }); } catch (error) { rejected = error; }
    assert.ok(rejected); assert.equal(rejected.stdout.toString(), ''); assert.ok(rejected.stderr.toString().includes('Explicit IDENTITY_AUTHORITY_REVIEW_DATABASE_URL'));
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test('staging cannot change actual group-derived application or license sources outside the inventory', async () => {
  const actor = await person(); const foreign = await person(); const groupId = randomUUID(); await pool.query('INSERT INTO groups(id,name) VALUES($1,$2)', [groupId, 'Owned legacy group untouched by authority staging']); await adoptTenant(database, schema, foreign.tenant, [{ kind: 'group', resourceId: groupId }]); const body = await manifest(actor);
  for (const operation of [client => client.query('INSERT INTO group_members(group_id,user_id) VALUES($1,$2)', [groupId, foreign.userId]), client => client.query("UPDATE groups SET name='Unrequested outside effect' WHERE id=$1", [groupId]), client => client.query('TRUNCATE group_members')]) {
    await assert.rejects(stage(body, operation), error => error.code === '42501'); assert.equal(await countCandidates(), 0);
  }
  assert.equal((await pool.query('SELECT name FROM groups WHERE id=$1', [groupId])).rows[0].name, 'Owned legacy group untouched by authority staging'); assert.equal((await pool.query('SELECT count(*)::int AS count FROM group_members WHERE group_id=$1', [groupId])).rows[0].count, 0);
});

test('quarantined expired sources neither become adopted nor shorten another coherent draft component', async () => {
  const actor = await person('admin'); const recipient = await person('user', actor.tenant); let expired;
  await database.transaction(async client => { expired = (await client.query("INSERT INTO identity_role_assignments(user_id,role,reason,expires_at) VALUES($1,'license-reader','Actual short source must stay quarantined after expiry',clock_timestamp()+interval '0.02 seconds') RETURNING id", [recipient.userId])).rows[0].id; }, { actor: JSON.stringify({ issuer, subject: actor.user.sub, userId: actor.userId }) }); await pool.query('SELECT pg_sleep(0.04)');
  const body = await manifest(actor, { adopt: true }); await assert.rejects(stage(body), error => error.code === '23514'); body.sources.find(source => source.id === expired).disposition = 'quarantine'; const result = await stage(body); assert.ok(Date.parse(result.validUntil) - Date.now() > 890000); assert.equal(result.quarantineIntentCount, 1);
});

test('actual mandatory legacy MFA and activation settings cannot be relaxed by an offline proposal', async () => {
  const actor = await person('admin'); const explanation = JSON.stringify({ issuer, subject: actor.user.sub, userId: actor.userId });
  async function configure(required, age, duration) { await database.transaction(async client => { await client.query("SELECT set_config('opendirectory.authentication_reason','Explicit existing assurance retained for migration test',true),set_config('opendirectory.activation_reason','Explicit existing activation retained for migration test',true)"); await client.query("UPDATE identity_role_authentication SET mfa_required=$1,max_age_seconds=$2,version=version+1 WHERE role='license-manager'", [required, age]); await client.query("UPDATE identity_role_activation_policies SET activation_required=$1,max_duration_seconds=$2,version=version+1 WHERE role='license-manager'", [required, duration]); }, { actor: explanation }); }
  try {
    await configure(true, 300, 600); const body = await manifest(actor); await assert.rejects(stage(body), error => error.code === '23514'); const profile = body.policies.find(policy => policy.role === 'license-manager'); profile.activation.required = true; profile.activation.maxDurationSeconds = 600; const weaker = structuredClone(body); weaker.policies.find(policy => policy.role === 'license-manager').authentication.required = false; await assert.rejects(stage(weaker), error => error.code === '23514'); const result = await stage(body); assert.equal(result.canAuthorize, false);
  } finally { await configure(false, 3600, 28800); }
});

test('a quarantine intention records the problem without falsely claiming to revoke the still-legacy active grant', async () => {
  const operator = await person('admin'); const foreign = await person(); await importForeignGrant(operator, foreign, 'Imported foreign source remains an explicitly unclosed legacy-source gap');
  const before = await new AuthorizationState(database).state(issuer, foreign.user.sub); const result = await stage(await manifest(foreign)); assert.equal(result.canAuthorize, false); assert.equal(result.adoptionIntentCount, 0); assert.ok(result.quarantineIntentCount > 0); assert.deepEqual(await new AuthorizationState(database).state(issuer, foreign.user.sub), before); assert.ok(before.roles.includes('license-manager'));
});

test('user inventories and their actual lock admission stay bounded without truncating an oversized tenant', async () => {
  const actor = await person(); const body = await manifest(actor); const added = (await pool.query("INSERT INTO users(id,username,email) SELECT gen_random_uuid(),'inventory-user-'||entry,'inventory-user-'||entry||'@test.invalid' FROM generate_series(1,1000) entry RETURNING id")).rows;
  await adoptTenant(database, schema, actor.tenant, added.map(account => ({ kind: 'user', resourceId: account.id }))); await assert.rejects(inventory(actor.tenant), error => error.code === '54000'); await assert.rejects(stage(body), error => error.code === '54000'); assert.equal(await countCandidates(), 0);
});

test('oversized canonical link history cannot be silently replaced by a hash of a truncated prefix', async () => {
  const actor = await person(); await database.transaction(client => client.query("INSERT INTO identity_subject_links(issuer,subject,user_id) SELECT 'https://alias-'||entry||'.test','owned-alias-'||entry,$1 FROM generate_series(1,1000) entry", [actor.userId])); await assert.rejects(inventory(actor.tenant), error => error.code === '54000'); assert.equal(await countCandidates(), 0);
});

test('the CLI refuses a plausible draft response without a real receiving row and same-transaction outbox', async () => {
  const actor = await person(); const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'od-authority-unconfirmed-')); const filename = path.join(directory, 'manifest.json'); const body = await manifest(actor); fs.writeFileSync(filename, JSON.stringify(body));
  await pool.query(`CREATE OR REPLACE FUNCTION identity_authority_stage(body JSONB) RETURNS jsonb LANGUAGE sql SET search_path=${schema},pg_catalog,pg_temp AS $$ SELECT jsonb_build_object('id',gen_random_uuid(),'tenantId',body->>'tenantId','state','draft','canAuthorize',false,'validUntil',clock_timestamp()+interval '15 minutes','manifestSha256',identity_authority_hash(body),'inventorySha256',body->>'inventorySha256','policyCount',jsonb_array_length(body->'policies'),'adoptionIntentCount',0,'quarantineIntentCount',jsonb_array_length(body->'sources')); $$`);
  try {
    let rejected; try { execFileSync(process.execPath, [path.join(__dirname, '../../scripts/authority-review.js'), 'stage', filename], { env: { ...process.env, IDENTITY_AUTHORITY_REVIEW_DATABASE_URL: process.env.IDENTITY_TEST_DATABASE_URL, IDENTITY_AUTHORITY_REVIEW_SCHEMA: schema }, stdio: 'pipe' }); } catch (error) { rejected = error; }
    assert.ok(rejected); assert.equal(rejected.stdout.toString(), ''); assert.ok(rejected.stderr.toString().includes('receiving receipt unavailable'), rejected.stderr.toString()); assert.equal(await countCandidates(), 0);
  } finally { await pool.query(fs.readFileSync(path.join(migrations, '030_authority_migration_candidates.sql'), 'utf8')); fs.rmSync(directory, { recursive: true, force: true }); }
});

test('a legacy link with a foreign retained subject binding is neither a canonical anchor nor an owned reviewer', async () => {
  const actor = await person('admin'); const voter = await person('pim-approver', actor.tenant); const foreign = await person();
  await pool.query('ALTER TABLE identity_subject_tenant_bindings DISABLE TRIGGER identity_subject_tenant_binding_guard');
  try { await pool.query('UPDATE identity_subject_tenant_bindings SET tenant_id=$1 WHERE issuer=$2 AND subject=$3', [foreign.tenant, issuer, voter.user.sub]); } finally { await pool.query('ALTER TABLE identity_subject_tenant_bindings ENABLE TRIGGER identity_subject_tenant_binding_guard'); }
  const current = await inventory(actor.tenant); assert.equal(current.data.users.find(account => account.id === voter.userId).canonical, false); assert.equal(current.data.sources.find(source => source.userId === voter.userId).live, false);
  const body = await manifest(actor); await assert.rejects(stage({ ...body, reviewAnchorUserId: voter.userId }), error => error.code === '23514'); const profile = body.policies.find(policy => policy.role === 'admin'); profile.activation.required = true; profile.activation.reviewerUserIds = [voter.userId]; await assert.rejects(stage(body), error => error.code === '23514'); assert.equal(await countCandidates(), 0);
});

test('a committed owned source plan has exact tenant-role identities but cannot change live authority or publish an active envelope', async () => {
  const actor = await person('admin'); const before = await new AuthorizationState(database).state(issuer, actor.user.sub); const candidate = await stage(await manifest(actor, { adopt: true }));
  const snapshot = await sourceSnapshot(candidate, actor); const result = resolveOwnedAuthorityPlan(snapshot);
  assert.equal(result.canAuthorize, false); assert.deepEqual(result.namespace.tenant, before.tenant); assert.equal(result.namespace.id, candidate.id); assert.equal(result.namespace.manifestSha256, candidate.manifestSha256);
  assert.deepEqual(result.users.find(account => account.userId === actor.userId).proposedRoles, ['admin']); assert.equal(result.active, undefined); assert.equal(result.context, undefined);
  assert.deepEqual(await new AuthorizationState(database).state(issuer, actor.user.sub), before); assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_authority_candidates')).rows[0].count, 1);
});

test('the planned source refuses the retained foreign role even while the unchanged legacy source remains positive', async () => {
  const actor = await person('admin'); const foreign = await person();
  const grant = await importForeignGrant(actor, foreign, 'Imported legacy source gap remains separate from non-authorizing planned source');
  const candidate = await stage(await manifest(foreign)); const result = resolveOwnedAuthorityPlan(await sourceSnapshot(candidate, foreign));
  assert.deepEqual(result.users.find(account => account.userId === foreign.userId).proposedRoles, []); assert.equal(result.assignments.find(assignment => assignment.id === grant.id).effectiveInPlan, false);
  assert.ok((await new AuthorizationState(database).state(issuer, foreign.user.sub)).roles.includes('license-manager'));
});

test('a proposed mandatory PIM policy cannot relabel an actual direct assignment as an owned activation', async () => {
  const actor = await person('admin'); const recipient = await person('user', actor.tenant);
  const grant = await new DirectoryRoles(database, { revalidate: async () => {} }).grant(recipient.userId, { role: 'license-manager', durationSeconds: 300, reason: 'Actual direct source must not satisfy proposed mandatory owned activation' }, actor.user);
  const body = await manifest(actor, { adopt: true }); body.policies.find(policy => policy.role === 'license-manager').activation.required = true;
  const candidate = await stage(body); const result = resolveOwnedAuthorityPlan(await sourceSnapshot(candidate, actor));
  assert.equal(result.assignments.find(assignment => assignment.id === grant.id).issue, 'owned_activation_required'); assert.deepEqual(result.users.find(account => account.userId === recipient.userId).proposedRoles, ['user']);
});

test('a shorter owned duration cannot extend or silently truncate a real retained source into compliance', async () => {
  const actor = await person('admin'); const recipient = await person('user', actor.tenant);
  const grant = await new DirectoryRoles(database, { revalidate: async () => {} }).grant(recipient.userId, { role: 'license-manager', durationSeconds: 300, reason: 'Retained original source requires separate legitimate shorter grant' }, actor.user);
  const body = await manifest(actor, { adopt: true }); body.policies.find(policy => policy.role === 'license-manager').activation.maxDurationSeconds = 60;
  const candidate = await stage(body); const result = resolveOwnedAuthorityPlan(await sourceSnapshot(candidate, actor)); assert.equal(result.assignments.find(assignment => assignment.id === grant.id).issue, 'duration_requires_new_grant');
  assert.equal((await pool.query('SELECT EXTRACT(EPOCH FROM expires_at-created_at)::int AS duration FROM identity_role_assignments WHERE id=$1', [grant.id])).rows[0].duration, 300);
});

test('proposed recurring governance cannot invent a missing initial review lease', async () => {
  const actor = await person('admin'); const recipient = await person('user', actor.tenant); const voter = await person('access-reviewer', actor.tenant);
  const grant = await new DirectoryRoles(database, { revalidate: async () => {} }).grant(recipient.userId, { role: 'license-manager', durationSeconds: 300, reason: 'Real source has no retained owned review lease to adopt' }, actor.user);
  const body = await manifest(actor, { adopt: true }); body.policies.find(policy => policy.role === 'license-manager').review = { intervalSeconds: 3600, windowSeconds: 60, reviewerUserIds: [voter.userId] };
  const candidate = await stage(body); const result = resolveOwnedAuthorityPlan(await sourceSnapshot(candidate, actor)); assert.equal(result.assignments.find(assignment => assignment.id === grant.id).issue, 'owned_review_required');
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_role_review_leases')).rows[0].count, 0);
});

test('known foreign or wrong-issuer candidate selectors fail before any foreign owner inventory is evaluated', async () => {
  const actor = await person(); const foreign = await person(); const candidate = await stage(await manifest(actor));
  await assert.rejects(sourceSnapshot(candidate, foreign), error => error.code === '23503');
  await assert.rejects(pool.query('SELECT identity_authority_candidate_snapshot($1,$2,$3)', [candidate.id, actor.tenant, 'https://foreign.test']), error => error.code === '23503');
  await assert.rejects(sourceSnapshot({ id: randomUUID() }, actor), error => error.code === '23503');
});

test('a source plan cannot confirm an uncommitted candidate before its deferred receiving checks', async () => {
  const actor = await person(); await assert.rejects(stage(await manifest(actor), (client, candidate) => sourceSnapshot(candidate, actor, client)), error => error.code === '42501'); assert.equal(await countCandidates(), 0);
});

test('changed users, source rows and shared legacy policy cannot be rebased into a reviewed owned source plan', async () => {
  const actor = await person('admin'); const candidate = await stage(await manifest(actor, { adopt: true }));
  await pool.query('UPDATE users SET authorization_revision=authorization_revision+1 WHERE id=$1', [actor.userId]); await assert.rejects(sourceSnapshot(candidate, actor), error => error.code === '42501');
  const next = await stage(await manifest(actor, { adopt: true }));
  await database.transaction(async client => { await client.query("SELECT set_config('opendirectory.authentication_reason','Explicit legacy policy drift makes reviewed owned source stale',true)"); await client.query("UPDATE identity_role_authentication SET mfa_required=true,max_age_seconds=300,version=version+1 WHERE role='license-manager'"); }, { actor: 'isolated-drift-test' });
  await assert.rejects(sourceSnapshot(next, actor), error => error.code === '42501');
});

test('missing guards and tampered receiving evidence cannot produce an owned source snapshot', async () => {
  const actor = await person(); const candidate = await stage(await manifest(actor));
  await pool.query('ALTER TABLE identity_authority_candidates DISABLE TRIGGER identity_authority_candidate_commit');
  try { await assert.rejects(sourceSnapshot(candidate, actor), error => error.code === '42501'); } finally { await pool.query('ALTER TABLE identity_authority_candidates ENABLE TRIGGER identity_authority_candidate_commit'); }
  await pool.query('ALTER TABLE identity_authority_candidate_events DISABLE TRIGGER identity_authority_candidate_evidence');
  try { await pool.query("UPDATE identity_authority_candidate_events SET actor='{}' WHERE id=$1", [candidate.id]); } finally { await pool.query('ALTER TABLE identity_authority_candidate_events ENABLE TRIGGER identity_authority_candidate_evidence'); }
  await assert.rejects(sourceSnapshot(candidate, actor), error => error.code === '42501');
});

test('the actual CLI source plan is read-only, owner-bound, redacted and explicitly incapable of authorization', async () => {
  const actor = await person('admin'); const candidate = await stage(await manifest(actor, { adopt: true })); const before = await new AuthorizationState(database).state(issuer, actor.user.sub);
  const output = execFileSync(process.execPath, [path.join(__dirname, '../../scripts/authority-review.js'), 'plan', candidate.id, actor.tenant, issuer], {
    env: { ...process.env, IDENTITY_AUTHORITY_REVIEW_DATABASE_URL: process.env.IDENTITY_TEST_DATABASE_URL, IDENTITY_AUTHORITY_REVIEW_SCHEMA: schema }, stdio: 'pipe', encoding: 'utf8' });
  const result = JSON.parse(output); assert.equal(result.canAuthorize, false); assert.equal(result.namespace.id, candidate.id); assert.deepEqual(result.users[0].proposedRoles, ['admin']);
  assert.equal(output.includes('private-'), false); assert.equal(output.includes('Private personal label'), false); assert.equal(output.includes('Explicit reviewed finite'), false);
  assert.deepEqual(await new AuthorizationState(database).state(issuer, actor.user.sub), before);
});

test('source-plan migration replay retains the draft and exact output without activating or cloning an authority namespace', async () => {
  const actor = await person('admin'); const candidate = await stage(await manifest(actor, { adopt: true })); const before = resolveOwnedAuthorityPlan(await sourceSnapshot(candidate, actor));
  await pool.query(fs.readFileSync(path.join(migrations, '031_authority_source_plans.sql'), 'utf8')); assert.deepEqual(resolveOwnedAuthorityPlan(await sourceSnapshot(candidate, actor)), before); assert.equal(await countCandidates(), 1);
});

test('actual already-active PIM lineage remains a bounded planned source without portable pending or approved authority', async () => {
  const actor = await person('admin'); const recipient = await person('user', actor.tenant); const store = new PrivilegedActivation(database, { revalidate: async () => {} });
  const eligibility = await store.grantEligibility({ userId: recipient.userId, role: 'license-manager', maxDurationSeconds: 300, validForSeconds: 3600, reason: 'Real same-owner eligibility for isolated source resolution' }, actor.user);
  const request = await store.request({ id: randomUUID(), eligibilityId: eligibility.id, durationSeconds: 300, reason: 'Actual independent approval before a finite activation' }, recipient.user);
  await store.change(request.id, 'approve', actor.user);
  const authTime = Math.floor(Date.now() / 1000); Object.assign(recipient.user, { auth_time: authTime, amr: ['pwd', 'otp'], mfa_authorization: { schemaVersion: 1, userId: recipient.userId, revision: '1', methods: ['pwd', 'otp'], authTime } });
  const active = await store.change(request.id, 'activate', recipient.user); assert.equal(active.status, 'active');
  const body = await manifest(actor, { adopt: true }); body.policies.find(policy => policy.role === 'license-manager').activation.required = true;
  const candidate = await stage(body); const snapshot = await sourceSnapshot(candidate, actor); const result = resolveOwnedAuthorityPlan(snapshot);
  assert.equal(result.assignments.find(assignment => assignment.id === active.assignmentId).effectiveInPlan, true); assert.deepEqual(result.users.find(account => account.userId === recipient.userId).proposedRoles, ['license-manager', 'user']);
  assert.equal(snapshot.inventory.sources.find(source => source.id === eligibility.id).state.policy_version, undefined);
  assert.deepEqual((await pool.query('SELECT id,expires_at FROM identity_role_assignments WHERE id=$1', [active.assignmentId])).rows.map(source => [source.id, source.expires_at.toISOString()]), [[active.assignmentId, active.expiresAt]]);
});

test('a real committed draft and its owned snapshot expire on the original physical source deadline', async () => {
  const actor = await person('admin'); const recipient = await person('user', actor.tenant);
  await database.transaction(client => client.query("INSERT INTO identity_role_assignments(user_id,role,reason,expires_at) VALUES($1,'license-reader','Physical short source limits the committed candidate snapshot',clock_timestamp()+interval '2 seconds')", [recipient.userId]), { actor: JSON.stringify({ issuer, subject: actor.user.sub, userId: actor.userId }) });
  const candidate = await stage(await manifest(actor, { adopt: true })); assert.equal((await sourceSnapshot(candidate, actor)).canAuthorize, false);
  await pool.query('SELECT pg_sleep(2.1)'); await assert.rejects(sourceSnapshot(candidate, actor), error => error.code === '42501');
});

test('a real low-privilege login and SET ROLE cannot obtain the owner-only source graph through a definer', async () => {
  const actor = await person(); const candidate = await stage(await manifest(actor)); const role = 'plan_limited_' + randomUUID().replaceAll('-', ''); let limited;
  await administration.query(`CREATE ROLE ${role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS`);
  try {
    await pool.query(`GRANT USAGE ON SCHEMA ${schema} TO ${role};GRANT EXECUTE ON FUNCTION identity_authority_candidate_snapshot(uuid,uuid,text) TO ${role}`);
    const address = new URL(process.env.IDENTITY_TEST_DATABASE_URL); address.username = role; limited = new Pool({ connectionString: address.toString(), max: 1, options: `-c search_path=${schema},public` });
    for (const assumed of [false, true]) {
      const client = await (assumed ? pool : limited).connect();
      try { await client.query('BEGIN'); if (assumed) await client.query('SET LOCAL ROLE ' + role); await assert.rejects(sourceSnapshot(candidate, actor, client), error => error.code === '42501' && error.message === 'Actual database owner required for offline authority review'); }
      finally { await client.query('ROLLBACK'); client.release(); }
    }
  } finally { await limited?.end(); await pool.query('DROP OWNED BY ' + role); await administration.query('DROP ROLE ' + role); }
});

test('the CLI refuses a plausible plan snapshot with no matching committed receiving row', async () => {
  const actor = await person('admin'); const candidate = await stage(await manifest(actor, { adopt: true })); const snapshot = await sourceSnapshot(candidate, actor); snapshot.candidateId = randomUUID();
  await pool.query(`CREATE OR REPLACE FUNCTION identity_authority_candidate_snapshot(identifier UUID,owner UUID,authority TEXT) RETURNS jsonb LANGUAGE sql SET search_path=${schema},pg_catalog,pg_temp AS $snapshot$ SELECT '${JSON.stringify(snapshot).replaceAll("'", "''")}'::jsonb; $snapshot$`);
  try {
    let rejected; try { execFileSync(process.execPath, [path.join(__dirname, '../../scripts/authority-review.js'), 'plan', snapshot.candidateId, actor.tenant, issuer], { env: { ...process.env, IDENTITY_AUTHORITY_REVIEW_DATABASE_URL: process.env.IDENTITY_TEST_DATABASE_URL, IDENTITY_AUTHORITY_REVIEW_SCHEMA: schema }, stdio: 'pipe' }); } catch (error) { rejected = error; }
    assert.ok(rejected); assert.equal(rejected.stdout.toString(), ''); assert.ok(rejected.stderr.toString().includes('source-plan receiving receipt unavailable'), rejected.stderr.toString());
  } finally { await pool.query(fs.readFileSync(path.join(migrations, '031_authority_source_plans.sql'), 'utf8')); }
});

test('review hashes, committed receipt scope and source-plan revisions are invariant across actual SQL session time zones', async () => {
  const actor = await person('admin'); const body = await manifest(actor, { adopt: true });
  const candidate = await database.transaction(async client => {
    await client.query("SET LOCAL timezone='Europe/Zurich'"); await client.query("SELECT set_config('opendirectory.authority_review','explicit-offline-authority-review',true)");
    return (await client.query('SELECT identity_authority_stage($1::jsonb) AS data', [JSON.stringify(body)])).rows[0].data;
  });
  const original = await sourceSnapshot(candidate, actor); const originalPlan = resolveOwnedAuthorityPlan(original);
  for (const timezone of ['UTC', 'Pacific/Honolulu', 'Asia/Kathmandu']) {
    const snapshot = await database.transaction(async client => { await client.query("SELECT set_config('TimeZone',$1,true)", [timezone]); return sourceSnapshot(candidate, actor, client); }, { readOnly: true });
    assert.deepEqual(snapshot, original); assert.deepEqual(resolveOwnedAuthorityPlan(snapshot), originalPlan);
  }
});
