'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { Pool } = require('pg');
const { ClientRegistry, etag } = require('../ClientRegistry');
const { hashSecret } = require('../clientSecrets');
const { ApplicationAccess } = require('../ApplicationAccess');
const actor = { iss: 'https://client-authority.test', sub: 'verified-operator', client_id: 'console', actor_type: 'user', roles: ['application-administrator'],
  identity_authorization: { userId: randomUUID(), revision: '1', linkRevision: '1', rolesRevision: 'a'.repeat(64) } };
const metadata = extra => ({ name: 'SQL application', redirectUris: ['https://sql-app.test/callback'], ...extra });
const migrations = path.join(__dirname, '../../migrations');
const seed = { clientId: 'explicit-bootstrap', clientSecretHash: hashSecret('explicit-disposable-secret'), publicClient: false, name: 'Explicit bootstrap',
  redirectUris: [], grantTypes: ['client_credentials'], scopes: ['openid'] };
async function authority(operation, { legacy = false } = {}) {
  const schema = 'oauth_clients_' + randomUUID().replaceAll('-', '');
  const administration = new Pool({ connectionString: process.env.OAUTH_TEST_DATABASE_URL, max: 1 });
  let pool;
  try {
    await administration.query(`CREATE SCHEMA ${schema}`);
    const url = new URL(process.env.OAUTH_TEST_DATABASE_URL); url.searchParams.set('options', `-c search_path=${schema},public`);
    pool = new Pool({ connectionString: url.toString(), max: 5 });
    for (const filename of fs.readdirSync(migrations).filter(filename => filename.endsWith('.sql')).sort()) {
      if (legacy && filename === '007_client_authority.sql') await pool.query(`INSERT INTO oauth_clients(id,name,secret,redirect_uris,grants,scopes)
        VALUES('legacy','Reviewed legacy','existing-disposable-secret','[]','["client_credentials"]','["openid"]')`);
      await pool.query(fs.readFileSync(path.join(migrations, filename), 'utf8'));
    }
    const database = { isAvailable: () => true, pool }; const registry = new ClientRegistry(database);
    await operation({ pool, registry, database });
  } finally {
    if (pool) await pool.end(); await administration.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`); await administration.end();
  }
}

test('migration hashes existing client secrets without importing new seed identities or changing client IDs', () => authority(async ({ pool, registry }) => {
  await registry.initialize([seed]);
  const row = (await pool.query("SELECT * FROM oauth_clients WHERE id='legacy'")).rows[0];
  assert.equal(row.secret, null); assert.equal(row.secret_hash, hashSecret('existing-disposable-secret')); assert.equal(row.revision, '1');
  assert.equal(row.token_endpoint_auth_method, 'client_secret_post');
  assert.equal(registry.authenticated(await registry.get('legacy'), 'existing-disposable-secret'), true);
  assert.equal(await registry.get(seed.clientId), null);
}, { legacy: true }));

test('empty storage bootstraps explicit identities once and never recreates a deleted last client', () => authority(async ({ pool, registry, database }) => {
  await registry.initialize([seed]); let client = await registry.get(seed.clientId); assert.ok(client);
  await registry.mutate(client.clientId, etag(client), null, actor, 'deleted');
  await new ClientRegistry(database).initialize([seed]); assert.equal(await registry.get(seed.clientId), null);
  assert.equal((await pool.query('SELECT initialized FROM oauth_client_registry')).rows[0].initialized, true);
  await assert.rejects(pool.query('UPDATE oauth_client_registry SET initialized=FALSE'));
}));

test('first-boot configuration mismatch rolls back both initial clients and initialization evidence', () => authority(async ({ pool, registry }) => {
  await assert.rejects(registry.initialize([seed], seed, () => { throw new Error('Reviewed configuration mismatch'); }), { status: 503 });
  assert.equal((await pool.query('SELECT COUNT(*)::int AS count FROM oauth_clients')).rows[0].count, 0);
  assert.equal((await pool.query('SELECT initialized FROM oauth_client_registry')).rows[0].initialized, false);
}));

test('SQL creation defaults disabled, stores only a hash and commits verified actor audit atomically', () => authority(async ({ pool, registry }) => {
  const created = await registry.create(metadata(), actor);
  const row = (await pool.query('SELECT * FROM oauth_clients WHERE id=$1', [created.clientId])).rows[0];
  assert.equal(row.enabled, false); assert.equal(row.secret, null); assert.equal(row.secret_hash, hashSecret(created.clientSecret));
  const audit = (await pool.query('SELECT * FROM oauth_client_audit WHERE client_id=$1', [created.clientId])).rows[0];
  assert.equal(audit.actor_subject, actor.sub); assert.equal(audit.actor_user_id, actor.identity_authorization.userId);
  for (const value of [JSON.stringify(audit), JSON.stringify(await registry.list(actor))]) {
    assert.ok(!value.includes(created.clientSecret)); assert.ok(!value.includes(row.secret_hash));
  }
}));

test('independent registries serialize conditional updates and keep the winning record', () => authority(async ({ registry, database }) => {
  const created = await registry.create(metadata(), actor); const other = new ClientRegistry(database);
  const results = await Promise.allSettled([registry.mutate(created.clientId, etag(created), { enabled: true }, actor), other.mutate(created.clientId, etag(created), { name: 'Other winner' }, actor)]);
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
  assert.equal(results.find(result => result.status === 'rejected').reason.status, 412);
  assert.equal((await other.get(created.clientId)).version, '2');
}));

test('rotation replaces the secret and generation for every process without retaining a usable previous credential', () => authority(async ({ pool, registry, database }) => {
  const created = await registry.create(metadata({ enabled: true }), actor); const other = new ClientRegistry(database);
  const previous = { client_id: created.clientId, client_revision: created.version, actor_type: 'user' };
  assert.equal(await other.active(previous), true);
  const rotated = await registry.mutate(created.clientId, etag(created), null, actor, 'rotated');
  assert.equal(await other.active(previous), false); assert.equal(await other.active({ ...previous, client_revision: rotated.version }), true);
  assert.equal(other.authenticated(await other.get(created.clientId), created.clientSecret), false);
  assert.equal(other.authenticated(await other.get(created.clientId), rotated.clientSecret), true);
  assert.equal((await pool.query('SELECT secret FROM oauth_clients WHERE id=$1', [created.clientId])).rows[0].secret, null);
}));

test('re-enabling or regranting identical scopes cannot resurrect an older generation', () => authority(async ({ registry }) => {
  let client = await registry.create(metadata({ enabled: true }), actor); const original = { client_id: client.clientId, client_revision: client.version, actor_type: 'user' };
  client = await registry.mutate(client.clientId, etag(client), { enabled: false }, actor); assert.equal(await registry.active(original), false);
  client = await registry.mutate(client.clientId, etag(client), { enabled: true }, actor); assert.equal(await registry.active(original), false);
  client = await registry.mutate(client.clientId, etag(client), { scopes: ['openid'] }, actor);
  await registry.mutate(client.clientId, etag(client), { scopes: ['openid','profile','email'] }, actor); assert.equal(await registry.active(original), false);
}));

test('failed SQL audit rolls back creation and rotation rather than acknowledging unknown credentials', () => authority(async ({ pool, registry }) => {
  const created = await registry.create(metadata({ enabled: true }), actor);
  await pool.query("CREATE FUNCTION fail_client_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture audit unavailable'; END $$");
  await pool.query('CREATE TRIGGER fail_client_audit BEFORE INSERT ON oauth_client_audit FOR EACH ROW EXECUTE FUNCTION fail_client_audit()');
  await assert.rejects(registry.create(metadata({ name: 'Must not commit' }), actor), { status: 503 });
  await assert.rejects(registry.mutate(created.clientId, etag(created), null, actor, 'rotated'), { status: 503 });
  assert.equal((await pool.query('SELECT COUNT(*)::int AS count FROM oauth_clients')).rows[0].count, 1);
  assert.equal((await registry.get(created.clientId)).version, created.version);
  assert.equal(registry.authenticated(await registry.get(created.clientId), created.clientSecret), true);
}));

test('client and audit SQL guards preserve immutable authentication type, versions and deletion evidence', () => authority(async ({ pool, registry }) => {
  const client = await registry.create(metadata(), actor);
  for (const sql of ["UPDATE oauth_clients SET revision=revision+2", "UPDATE oauth_clients SET token_endpoint_auth_method='none',secret_hash=NULL,revision=revision+1", "UPDATE oauth_clients SET secret='plaintext',revision=revision+1", 'DELETE FROM oauth_clients', "UPDATE oauth_client_audit SET actor_subject='forged'", 'DELETE FROM oauth_client_audit']) await assert.rejects(pool.query(sql));
  await registry.mutate(client.clientId, etag(client), null, actor, 'deleted');
  await assert.rejects(pool.query('UPDATE oauth_clients SET enabled=TRUE,deleted_at=NULL,revision=revision+1'));
  await assert.rejects(pool.query('UPDATE oauth_clients SET name=$1,revision=revision+1', ['Recreated']));
}));

test('migration reapplication never resets a rotated secret, generation, tombstone or audited decision', () => authority(async ({ pool, registry }) => {
  let client = await registry.create(metadata(), actor); client = await registry.mutate(client.clientId, etag(client), null, actor, 'rotated');
  await registry.mutate(client.clientId, etag(client), null, actor, 'deleted');
  const before = (await pool.query('SELECT * FROM oauth_clients')).rows;
  await pool.query(fs.readFileSync(path.join(migrations, '007_client_authority.sql'), 'utf8'));
  assert.deepEqual((await pool.query('SELECT * FROM oauth_clients')).rows, before);
  assert.equal((await pool.query('SELECT COUNT(*)::int AS count FROM oauth_client_audit')).rows[0].count, 3);
}));

test('a missing or corrupted live registry cannot use an older positive authorization', () => authority(async ({ pool, registry }) => {
  const created = await registry.create(metadata({ enabled: true }), actor); const token = { client_id: created.clientId, client_revision: created.version, actor_type: 'user' };
  assert.equal(await registry.active(token), true);
  await pool.query('ALTER TABLE oauth_clients RENAME TO unavailable_clients');
  try { await assert.rejects(registry.active(token), { status: 503 }); }
  finally { await pool.query('ALTER TABLE unavailable_clients RENAME TO oauth_clients'); }
  assert.equal(await registry.active(token), true);
  await pool.query("UPDATE oauth_clients SET scopes='[1]'::jsonb,revision=revision+1");
  await assert.rejects(registry.get(created.clientId), { status: 503, code: 'invalid_client_record' });
}));

test('a blocked SQL read is cancelled server-side and later recovers without authorizing from cache', () => authority(async ({ pool, registry }) => {
  const created = await registry.create(metadata({ enabled: true }), actor); const connection = await pool.connect();
  await connection.query('BEGIN'); await connection.query('LOCK oauth_clients IN ACCESS EXCLUSIVE MODE');
  const started = Date.now();
  try { await assert.rejects(registry.active({ client_id: created.clientId, client_revision: created.version, actor_type: 'user' }), { status: 503 }); assert.ok(Date.now() - started < 4000); }
  finally { await connection.query('ROLLBACK'); connection.release(); }
  assert.equal(await registry.active({ client_id: created.clientId, client_revision: created.version, actor_type: 'user' }), true);
}));

const accessActor = { ...actor,roles: ['application-access-administrator'] };
const recipient = randomUUID(); const membershipGroup = randomUUID();
const grantInput = extra => ({ requestId: randomUUID(),targetType: 'user',targetId: recipient,durationSeconds: 3600,reason: 'Reviewed SQL application entitlement',...extra });
const identityProof = { target: async (targetType,targetId,actorUserId) => ({ targetType,targetId,active: true,revision: '1',actorIsMember: targetType === 'user' && targetId === actorUserId }) };
const canonicalState = memberships => ({ context: { userId: recipient,revision: '1',linkRevision: '1',rolesRevision: 'a'.repeat(64) },memberships });
async function assignmentFixture(values) {
  const client = await values.registry.create(metadata({ enabled: true }),actor);
  return { client,access: new ApplicationAccess(values.database,{ identity: identityProof }) };
}
test('mandatory application assignment denies even global roles until an explicit canonical entitlement exists', () => authority(async values => {
  const { client,access } = await assignmentFixture(values); const state = canonicalState([]);
  await assert.rejects(access.context(client.clientId,{ ...state,authorization: { roles: ['admin'] } }),{ status: 403 });
  const granted = await access.grant(client.clientId,grantInput(),accessActor); assert.equal(granted.reused,false);
  assert.ok(await access.context(client.clientId,state));
  const audit = (await values.pool.query('SELECT * FROM oauth_application_access_audit')).rows[0];
  assert.equal(audit.actor.subject,accessActor.sub); assert.equal(audit.actor.userId,actor.identity_authorization.userId); assert.equal(audit.action,'granted');
}));
test('assignment retries bind the immutable request to canonical actor, target, client and duration without duplicate audit', () => authority(async values => {
  const { client,access } = await assignmentFixture(values); const input = grantInput();
  const first = await access.grant(client.clientId,input,accessActor); const repeated = await access.grant(client.clientId,input,accessActor); assert.equal(repeated.reused,true); assert.equal(first.assignment.id,repeated.assignment.id);
  for (const changed of [{ ...input,targetId: randomUUID() },{ ...input,durationSeconds: 7200 },{ ...input,reason: 'Different reviewed reason' }]) await assert.rejects(access.grant(client.clientId,changed,accessActor),{ status: 409 });
  await assert.rejects(access.grant(client.clientId,input,{ ...accessActor,sub: 'other-actor' }),{ status: 409 });
  assert.equal((await values.pool.query('SELECT COUNT(*)::int AS count FROM oauth_application_access_audit')).rows[0].count,1);
}));
test('independent assignment writers serialize on the canonical client and cannot duplicate an active target lease', () => authority(async values => {
  const { client,access } = await assignmentFixture(values); const other = new ApplicationAccess(values.database,{ identity: identityProof });
  const results = await Promise.allSettled([access.grant(client.clientId,grantInput(),accessActor),other.grant(client.clientId,grantInput(),accessActor)]);
  assert.equal(results.filter(result => result.status === 'fulfilled').length,1); assert.equal(results.find(result => result.status === 'rejected').reason.status,409);
  assert.equal((await values.pool.query('SELECT COUNT(*)::int AS count FROM oauth_application_assignments')).rows[0].count,1);
}));
test('direct/group overlap preserves a new sign-in path while revocation and membership re-add cannot revive old contexts', () => authority(async values => {
  const { client,access } = await assignmentFixture(values);
  const direct = await access.grant(client.clientId,grantInput(),accessActor); const group = await access.grant(client.clientId,grantInput({ targetType: 'group',targetId: membershipGroup }),accessActor);
  const state = canonicalState([{ groupId: membershipGroup,membershipId: randomUUID() }]); const original = await access.context(client.clientId,state);
  await access.revoke(client.clientId,direct.assignment.id,accessActor); assert.equal(await access.matches(client.clientId,state,original),false);
  const groupOnly = await access.context(client.clientId,state); assert.equal(await access.matches(client.clientId,canonicalState([]),groupOnly),false);
  assert.equal(await access.matches(client.clientId,canonicalState([{ groupId: membershipGroup,membershipId: randomUUID() }]),groupOnly),false);
  await access.revoke(client.clientId,group.assignment.id,accessActor); await assert.rejects(access.context(client.clientId,state),{ status: 403 });
  await access.grant(client.clientId,grantInput(),accessActor); assert.equal(await access.matches(client.clientId,state,original),false);
}));
test('assignment expiry is live and an explicitly regranted lease cannot restore the old fingerprint', () => authority(async values => {
  const { client,access } = await assignmentFixture(values); const first = await access.grant(client.clientId,grantInput(),accessActor); const state = canonicalState([]);
  const original = await access.context(client.clientId,state);
  await values.pool.query('ALTER TABLE oauth_application_assignments DISABLE TRIGGER oauth_application_assignment_guard');
  await values.pool.query('ALTER TABLE oauth_application_assignments DISABLE TRIGGER oauth_application_assignment_record');
  try { await values.pool.query("UPDATE oauth_application_assignments SET expires_at=clock_timestamp()+interval '0.15 seconds' WHERE id=$1",[first.assignment.id]); }
  finally { await values.pool.query('ALTER TABLE oauth_application_assignments ENABLE TRIGGER oauth_application_assignment_guard'); await values.pool.query('ALTER TABLE oauth_application_assignments ENABLE TRIGGER oauth_application_assignment_record'); }
  await new Promise(resolve => setTimeout(resolve,220)); assert.equal(await access.matches(client.clientId,state,original),false);
  await access.grant(client.clientId,grantInput(),accessActor); assert.equal(await access.matches(client.clientId,state,original),false);
}));
test('assignment audit failures roll back both grants and revocation without false success', () => authority(async values => {
  const { client,access } = await assignmentFixture(values); const first = await access.grant(client.clientId,grantInput(),accessActor);
  await values.pool.query("CREATE FUNCTION fail_assignment_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture audit offline'; END $$");
  await values.pool.query('CREATE TRIGGER fail_assignment_audit BEFORE INSERT ON oauth_application_access_audit FOR EACH ROW EXECUTE FUNCTION fail_assignment_audit()');
  await assert.rejects(access.grant(client.clientId,grantInput({ targetId: randomUUID() }),accessActor),{ status: 503 });
  await assert.rejects(access.revoke(client.clientId,first.assignment.id,accessActor),{ status: 503 });
  assert.equal((await values.pool.query('SELECT COUNT(*)::int AS count FROM oauth_application_assignments')).rows[0].count,1);
  assert.ok(await access.context(client.clientId,canonicalState([])));
}));
test('assignment SQL guards retain immutable origin, deadlines, target, actor and one-way revocation', () => authority(async values => {
  const { client,access } = await assignmentFixture(values); const first = await access.grant(client.clientId,grantInput(),accessActor);
  for (const sql of ['DELETE FROM oauth_application_assignments',"UPDATE oauth_application_assignments SET expires_at=expires_at+interval '1 day'","UPDATE oauth_application_access_audit SET actor='{}'::jsonb",'DELETE FROM oauth_application_access_audit']) await assert.rejects(values.pool.query(sql));
  await access.revoke(client.clientId,first.assignment.id,accessActor);
  await assert.rejects(values.pool.query('UPDATE oauth_application_assignments SET revoked_at=NULL'));
  await assert.rejects(access.grant(client.clientId,{ ...grantInput(),requestId: first.assignment.id },accessActor),{ status: 409 });
  const before = (await values.pool.query('SELECT * FROM oauth_application_assignments')).rows;
  await values.pool.query(fs.readFileSync(path.join(migrations,'008_application_access.sql'),'utf8')); assert.deepEqual((await values.pool.query('SELECT * FROM oauth_application_assignments')).rows,before);
}));
test('application metadata administrators cannot assign access, and access staff cannot take over protected clients or themselves', () => authority(async values => {
  const { client,access } = await assignmentFixture(values);
  await assert.rejects(access.grant(client.clientId,grantInput(),actor),{ status: 403 });
  await assert.rejects(access.grant(client.clientId,grantInput({ targetId: accessActor.identity_authorization.userId }),accessActor),{ status: 403 });
  const protectedApp = await values.registry.create(metadata({ scopes: ['roles'] }),{ ...actor,roles: ['admin'] });
  await assert.rejects(access.grant(protectedApp.clientId,grantInput(),accessActor),{ status: 403 });
  await access.grant(protectedApp.clientId,grantInput(),{ ...actor,roles: ['admin'] });
  assert.equal((await access.list(protectedApp.clientId,{ ...accessActor,roles: ['application-access-reader'] })).canManage,false);
}));
test('assignment storage outage cannot substitute a cached entitlement and does not spend an immutable request', () => authority(async values => {
  const { client,access } = await assignmentFixture(values); await access.grant(client.clientId,grantInput(),accessActor); const state = canonicalState([]); const original = await access.context(client.clientId,state);
  await values.pool.query('ALTER TABLE oauth_application_assignments RENAME TO unavailable_assignments');
  try { await assert.rejects(access.matches(client.clientId,state,original),{ status: 503 }); }
  finally { await values.pool.query('ALTER TABLE unavailable_assignments RENAME TO oauth_application_assignments'); }
  assert.equal(await access.matches(client.clientId,state,original),true);
}));
test('offline application bootstrap is bounded, audited and never fabricates a group or permanent grant', () => authority(async values => {
  const { client,access } = await assignmentFixture(values);
  const result = await access.bootstrap(client.clientId,recipient,3600,'Reviewed independent recovery access',actor.iss);
  assert.equal(result.assignment.durationSeconds,3600); assert.equal((await values.pool.query('SELECT action FROM oauth_application_access_audit')).rows[0].action,'bootstrap');
  await assert.rejects(access.bootstrap(client.clientId,randomUUID(),28801,'Reviewed recovery too long',actor.iss),{ status: 400 });
}));
