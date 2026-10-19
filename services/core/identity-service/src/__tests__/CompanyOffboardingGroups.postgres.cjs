'use strict';

const { test, before, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID, createHash } = require('node:crypto');
const { Pool } = require('pg');
const { CompanyOffboardingGroups } = require('../CompanyOffboardingGroups');
const { CompanyOffboarding } = require('../CompanyOffboarding');
const { CompanyRegistrations } = require('../CompanyRegistrations');
const { CompanyRegistrationReviews } = require('../CompanyRegistrationReviews');
const { AuthorizationState } = require('../AuthorizationState');
const { DirectoryCreator } = require('../DirectoryCreator');
const { DirectoryUsers, userEtag } = require('../DirectoryUsers');
const { UserMutator } = require('../UserMutator');
const { GroupMutator, groupEtag } = require('../GroupMutator');
const { sameContext } = require('../../../../../packages/identity-authorization-contract');
const { provisionTenant, adoptTenant } = require('../../../../../scripts/lib/tenant-ownership-fixture.cjs');
const { changeOperator } = require('../../scripts/company-review-operator');
const { PURPOSE, AUDIENCE, BASE_PATH } = require('../../../../../packages/company-registration-contract');
const { requestDigest } = require('../../../../../packages/company-registration-contract/digest');
const schema = 'offboarding_groups_' + randomUUID().replaceAll('-', '');
const issuer = 'https://offboarding-groups.test';
const authorization = 'Bearer original-cleanup-' + randomUUID();
const administration = new Pool({ connectionString: process.env.IDENTITY_TEST_DATABASE_URL, max: 1 });
let database; let pool;
before(async () => {
  await administration.query('CREATE SCHEMA ' + schema);
  const address = new URL(process.env.IDENTITY_TEST_DATABASE_URL); address.searchParams.set('options', '-c search_path=' + schema + ',public');
  process.env.DATABASE_URL = address.toString(); database = require('../db'); pool = database.pool;
  assert.equal(await database.initDb(), true);
  assert.equal((await pool.query("SELECT count(*)::int AS count FROM pg_proc WHERE pronamespace=$1::regnamespace AND proname='identity_company_offboarding_groups_begin'", [schema])).rows[0].count, 1);
});
beforeEach(async () => {
  const guarded = [['identity_company_offboarding_receipts', 'identity_company_offboarding_no_truncate'], ['identity_company_offboarding_outbox', 'identity_company_offboarding_no_truncate'],
    ...['identity_company_offboarding_group_receipts', 'identity_company_offboarding_group_outbox', 'identity_company_offboarding_group_checks'].map(table => [table, 'identity_company_offboarding_groups_no_truncate'])];
  for (const [table, trigger] of guarded) await pool.query('ALTER TABLE ' + table + ' DISABLE TRIGGER ' + trigger);
  try { await pool.query('TRUNCATE identity_tenants,users,groups,ous,identity_deleted_users,identity_directory_user_events,identity_directory_group_events,identity_company_offboarding_receipts CASCADE'); }
  finally { for (const [table, trigger] of guarded) await pool.query('ALTER TABLE ' + table + ' ENABLE TRIGGER ' + trigger); }
});
after(async () => { await pool?.end(); await administration.query('DROP SCHEMA ' + schema + ' CASCADE'); await administration.end(); });
async function token(userId, subject) {
  const state = await new AuthorizationState(database).state(issuer, subject); const now = Math.floor(Date.now() / 1000);
  return { iss: issuer, sub: subject, actor_type: 'user', roles: state.roles, identity_authorization: state.context, jti: randomUUID(), exp: now + 600,
    auth_time: now, amr: ['pwd', 'otp'], mfa_authorization: { schemaVersion: 1, userId, revision: '1', authTime: now, methods: ['pwd', 'otp'] } };
}
function settings(live = {}) {
  return { issuer, revalidate: async (bearer, user) => {
    assert.equal(bearer, authorization); if (live.check) await live.check();
    const state = await new AuthorizationState(database).state(issuer, user.sub);
    if (live.withdrawn || !state.active || !sameContext(state.context, user.identity_authorization)) throw Object.assign(new Error('Original source withdrawn'), { status: 401 });
    return state.tenant;
  } };
}
async function administrator(tenant, role = 'admin') {
  tenant ||= await provisionTenant(database, schema, { enabled: true }); const userId = randomUUID(); const subject = 'admin-' + userId;
  await pool.query('INSERT INTO users(id,username,email) VALUES($1,$2,$3)', [userId, subject, subject + '@test.invalid']);
  await pool.query('INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES($1,$2,$3)', [issuer, subject, userId]);
  await adoptTenant(database, schema, tenant, [{ kind: 'user', resourceId: userId }]);
  if (role) await pool.query('INSERT INTO identity_role_assignments(user_id,role,reason) VALUES($1,$2,$3)', [userId, role, 'Explicit canonical cleanup operator fixture']);
  return { user: await token(userId, subject), tenant };
}
async function owner() {
  const reviewer = await administrator(undefined, null); const reviewerId = reviewer.user.identity_authorization.userId;
  await changeOperator(database, { issuer, userId: reviewerId, version: '0', enabled: true, reason: 'Explicit independent registration reviewer fixture' });
  reviewer.user = await token(reviewerId, reviewer.user.sub);
  const subject = 'owner-' + randomUUID(); const value = { registrationId: randomUUID(), subject,
    principal: { username: subject, email: subject + '@test.invalid', displayName: 'Actual roleless owner' },
    profile: { name: 'Group Cleanup AG', legalForm: 'AG', registrationNumber: '', taxId: '', addressLine1: 'Test Street 1', addressLine2: '',
      postalCode: '8000', city: 'Zürich', country: 'CH', timezone: 'UTC', defaultLanguage: 'de', contactEmail: 'office@test.invalid', contactPhone: '', website: '' } };
  const store = new CompanyRegistrations(database);
  const receive = (operation, body) => { const now = Math.floor(Date.now() / 1000); return store.receive(operation, body, { iss: issuer, sub: 'oauth-provider', aud: AUDIENCE,
    token_use: PURPOSE, actor_type: 'workload', htm: 'POST', htu: BASE_PATH + '/' + operation, body_sha256: requestDigest(operation, body), registration_subject: subject,
    jti: randomUUID(), iat: now, exp: now + 30 }); };
  await receive('submit', value); const reviews = new CompanyRegistrationReviews(database, { revalidate: (user, bearer) => settings().revalidate(bearer, user) });
  const pending = await reviews.get(value.registrationId, reviewer.user);
  await reviews.decide(value.registrationId, { decision: 'approved', reason: 'Independent actual company approval', confirm: true }, pending.etag, reviewer.user, authorization);
  const activated = await receive('activate', { registrationId: value.registrationId, subject, consoleClientId: 'web-app' });
  return { user: await token(activated.administratorId, subject), tenant: activated.tenantId };
}
async function person(actor) {
  const created = await new DirectoryCreator(database, settings()).user({ username: 'employee-' + randomUUID(), email: randomUUID() + '@test.invalid' }, actor.user, authorization);
  return new UserMutator(database, settings()).update(created.id, { enabled: true }, userEtag(created), actor.user, authorization);
}
const service = (db = database, options = settings()) => new CompanyOffboardingGroups(db, options);
const loadGroup = async groupId => (await pool.query('SELECT id,name,revision::text AS revision FROM groups WHERE id=$1', [groupId])).rows[0];
const groupLinks = async groupId => (await pool.query('SELECT group_id,user_id,membership_id FROM group_members WHERE group_id=$1 ORDER BY user_id', [groupId])).rows;
async function linkedGroup(actor, target, second) {
  let group = await new DirectoryCreator(database, settings()).group({ name: 'Group ' + randomUUID() }, actor.user, authorization);
  group = await new GroupMutator(database, settings()).add(group.id, { userId: target.id }, groupEtag(group), actor.user, authorization);
  if (second) group = await new GroupMutator(database, settings()).add(group.id, { userId: second.id }, groupEtag(group), actor.user, authorization);
  return group;
}
async function fixture(count = 2, roleless = false) {
  const actor = roleless ? await owner() : await administrator(); const target = await person(actor); const second = await person(actor);
  const groups = [];
  for (let index = 0; index < count; index++) groups.push(await linkedGroup(actor, target, second));
  const parent = await new CompanyOffboarding(database, settings()).receive(target.id, { workflowId: randomUUID(), expectedRevision: target.revision, confirm: true }, actor.user, authorization);
  const preview = await service().preview(target.id, { workflowId: parent.workflowId }, actor.user, authorization);
  const intent = { workflowId: parent.workflowId, eligibilityRevision: parent.afterEligibilityRevision, reason: 'Remove captured employee group memberships', confirm: true,
    memberships: preview.groups.map(({ groupId, groupRevision, membershipId }) => ({ groupId, groupRevision, membershipId })) };
  return { actor, target, second, groups, parent, preview, intent };
}
const remove = (value, db = database, options = settings()) => service(db, options).remove(value.target.id, value.intent, value.actor.user, authorization);
const receipts = async () => (await pool.query('SELECT * FROM identity_company_offboarding_group_receipts ORDER BY created_at,id')).rows;
function wrapped({ query, afterCommit, beforeCommit, onError } = {}) {
  return { ...database, transaction: async (operation, options = {}) => {
    const result = await database.transaction(client => operation({ query: async (sql, values) => {
      if (query) return query(client, sql, values, options); return client.query(sql, values);
    } }), { ...options, beforeCommit: async client => { await options.beforeCommit?.(client); if (!options.readOnly) await beforeCommit?.(client); } }).catch(error => { onError?.(error); throw error; });
    if (!options.readOnly) await afterCommit?.(result); return result;
  } };
}

test('actual roleless Owner disables canonically and removes two owned links with exact retained native events and unaffected second person', async () => {
  const value = await fixture(2, true); assert.deepEqual(value.actor.user.roles, []);
  const secondBefore = await new DirectoryUsers(database).get(value.second.id); let childError;
  const result = await remove(value, wrapped({ onError: error => { childError = error; } }));
  assert.deepEqual(Object.keys(result), ['schemaVersion', 'actorUserId', 'tenantId', 'workflowId', 'userId', 'correlationId', 'results']);
  assert.equal(result.results.length, 2); assert.ok(result.results.every(item => item.status === 'removed' && item.code === 200 && item.operationId), childError?.stack + '\n' + childError?.where);
  const retained = await receipts(); assert.equal(retained.length, 2);
  for (const row of retained) {
    assert.equal(row.source.tokenSha256, createHash('sha256').update(authorization).digest('hex'));
    assert.equal(row.eligibility_revision, value.parent.afterEligibilityRevision);
    await pool.query('SELECT identity_company_offboarding_group_validate($1)', [row.id]);
    const links = await groupLinks(row.group_id); assert.deepEqual(links.map(link => link.user_id), [value.second.id]);
  }
  assert.deepEqual(await new DirectoryUsers(database).get(value.second.id), secondBefore);
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_role_assignments WHERE user_id=$1', [value.actor.user.identity_authorization.userId])).rows[0].count, 0);
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_company_offboarding_group_outbox')).rows[0].count, 2);
  assert.equal(JSON.stringify(retained).includes(authorization), false); assert.equal(JSON.stringify(retained).includes(value.actor.user.jti), false);
  const history = await service().history(value.target.id, { workflowId: value.parent.workflowId }, value.actor.user, authorization);
  assert.equal(history.total, 2); assert.ok(history.receipts.every(row => row.deliveryStatus === 'pending'));
});

test('actual 26-group pagination removes only the captured 25 and leaves the 26th group UUID, version and link unchanged', async () => {
  const value = await fixture(26); assert.equal(value.preview.total, 26); assert.equal(value.preview.groups.length, 25);
  const page = await service().preview(value.target.id, { workflowId: value.parent.workflowId, page: '2', limit: '25' }, value.actor.user, authorization);
  assert.equal(page.groups.length, 1); const untouched = page.groups[0]; const links = await groupLinks(untouched.groupId);
  const result = await remove(value); assert.equal(result.results.length, 25); assert.ok(result.results.every(item => item.status === 'removed'));
  assert.deepEqual(await loadGroup(untouched.groupId), { id: untouched.groupId, name: untouched.name, revision: untouched.groupRevision });
  assert.deepEqual(await groupLinks(untouched.groupId), links); assert.equal((await receipts()).length, 25);
  const remaining = await service().preview(value.target.id, { workflowId: value.parent.workflowId }, value.actor.user, authorization);
  assert.equal(remaining.total, 1); assert.deepEqual(remaining.groups, [untouched]);
});

test('later foreign or stale manifest items fail the whole read-only preflight before any removal attempts', async () => {
  const value = await fixture(); const foreign = await administrator(); const foreignPerson = await person(foreign); const foreignGroup = await linkedGroup(foreign, foreignPerson);
  const foreignLink = (await groupLinks(foreignGroup.id))[0];
  const original = value.intent.memberships; const before = await groupLinks(original[0].groupId);
  let attempts = 0; const observed = wrapped({ query: async (client, sql, values) => { if (sql.startsWith('DELETE FROM group_members')) attempts++; return client.query(sql, values); } });
  for (const [member, status] of [[{ groupId: foreignGroup.id, groupRevision: foreignGroup.revision, membershipId: foreignLink.membership_id }, 404],
    [{ ...original[1], groupRevision: '9223372036854775807' }, 412], [{ ...original[1], membershipId: randomUUID() }, 409]]) {
    value.intent = { ...value.intent, memberships: [original[0], member] };
    await assert.rejects(remove(value, observed), error => error.status === status);
  }
  assert.equal(attempts, 0); assert.equal((await receipts()).length, 0); assert.deepEqual(await groupLinks(original[0].groupId), before);
});

test('later revision conflict preserves first committed child and stops the third item', async () => {
  const value = await fixture(3); let committed = false;
  const observed = wrapped({ afterCommit: async () => {
    if (committed) return; committed = true; const group = await loadGroup(value.intent.memberships[1].groupId);
    await new GroupMutator(database, settings()).update(group.id, { name: 'Concurrent actual group revision change' }, groupEtag(group), value.actor.user, authorization);
  } });
  const result = await remove(value, observed);
  assert.deepEqual(result.results.map(item => [item.status, item.code]), [['removed', 200], ['unconfirmed', 412], ['not_attempted', null]]);
  assert.equal((await receipts()).length, 1); assert.equal((await groupLinks(value.intent.memberships[2].groupId)).length, 2);
});

test('lost driver ACK after COMMIT yields unconfirmed, then old-manifest recovery retains operation and never deletes a regrant', async () => {
  const value = await fixture(); let lost = false;
  const result = await remove(value, wrapped({ afterCommit: async () => { if (!lost) { lost = true; throw new Error('Lost driver acknowledgement after COMMIT'); } } }));
  assert.deepEqual(result.results.map(item => item.status), ['unconfirmed', 'not_attempted']); assert.equal(result.results[0].operationId, null);
  const retained = (await receipts())[0]; let group = await loadGroup(retained.group_id);
  group = await new GroupMutator(database, settings()).add(group.id, { userId: value.target.id }, groupEtag(group), value.actor.user, authorization);
  const regrant = (await groupLinks(group.id)).find(link => link.user_id === value.target.id); assert.notEqual(regrant.membership_id, retained.membership_id);
  const recovered = await remove(value); assert.equal(recovered.results[0].status, 'already_removed'); assert.equal(recovered.results[0].operationId, retained.operation_id);
  assert.deepEqual((await groupLinks(group.id)).find(link => link.user_id === value.target.id), regrant); assert.equal((await loadGroup(group.id)).revision, group.revision);
  assert.equal((await receipts()).length, 2);
});

test('history and already_removed survive actual later group deletion with retained original name and version', async () => {
  const value = await fixture(1); const result = await remove(value); const member = value.intent.memberships[0]; const group = await loadGroup(member.groupId);
  await new GroupMutator(database, settings()).remove(group.id, groupEtag(group), value.actor.user, authorization);
  const recovered = await remove(value); assert.equal(recovered.results[0].status, 'already_removed'); assert.equal(recovered.results[0].operationId, result.results[0].operationId);
  const history = await service().history(value.target.id, { workflowId: value.parent.workflowId }, value.actor.user, authorization);
  assert.equal(history.receipts[0].name, value.preview.groups[0].name); assert.equal(history.receipts[0].beforeGroupRevision, member.groupRevision);
});

test('missing/wrong parent, disabled eligibility substitution and reenabled then redisabled generations fail closed', async () => {
  const value = await fixture(1); const original = value.intent;
  for (const changed of [{ ...original, workflowId: randomUUID() }, { ...original, eligibilityRevision: '9223372036854775807' }]) {
    value.intent = changed; await assert.rejects(remove(value), error => error.status === 409);
  }
  value.intent = original;
  await assert.rejects(service().preview(value.second.id, { workflowId: original.workflowId }, value.actor.user, authorization), error => error.status === 409);
  let target = await new DirectoryUsers(database).get(value.target.id);
  target = await new UserMutator(database, settings()).update(target.id, { enabled: true }, userEtag(target), value.actor.user, authorization);
  await assert.rejects(remove(value), error => error.status === 409);
  await new UserMutator(database, settings()).update(target.id, { enabled: false }, userEtag(target), value.actor.user, authorization);
  for (const method of ['preview', 'history']) await assert.rejects(service()[method](target.id, { workflowId: original.workflowId }, value.actor.user, authorization), error => error.code === '23514' || error.status === 409);
  await assert.rejects(remove(value), error => error.status === 409); assert.equal((await receipts()).length, 0);
});

test('foreign imported target links fail preview without exposing foreign group names', async () => {
  const value = await fixture(1); const foreign = await administrator(); const foreignPerson = await person(foreign); const group = await linkedGroup(foreign, foreignPerson);
  await pool.query('ALTER TABLE group_members DISABLE TRIGGER aaa_identity_tenant_membership_guard');
  try { await pool.query('INSERT INTO group_members(group_id,user_id) VALUES($1,$2)', [group.id, value.target.id]); }
  finally { await pool.query('ALTER TABLE group_members ENABLE TRIGGER aaa_identity_tenant_membership_guard'); }
  await assert.rejects(service().preview(value.target.id, { workflowId: value.parent.workflowId }, value.actor.user, authorization), error => error.status === 503);
});

test('missing receivers and suppressed mandatory child or cleanup evidence cannot commit a removal', async () => {
  const value = await fixture(1); const before = await groupLinks(value.groups[0].id);
  for (const table of ['identity_directory_group_outbox', 'identity_group_outbox', 'identity_company_offboarding_group_receipts', 'identity_company_offboarding_group_outbox', 'identity_company_offboarding_group_checks']) {
    await pool.query('CREATE FUNCTION cleanup_omit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL;END $$;CREATE TRIGGER zz_cleanup_omit BEFORE INSERT ON ' + table + ' FOR EACH ROW EXECUTE FUNCTION cleanup_omit()');
    try { const result = await remove(value); assert.equal(result.results[0].status, 'unconfirmed'); }
    finally { await pool.query('DROP TRIGGER zz_cleanup_omit ON ' + table + ';DROP FUNCTION cleanup_omit()'); }
    assert.equal((await receipts()).length, 0); assert.deepEqual(await groupLinks(value.groups[0].id), before);
  }
  await pool.query('ALTER TABLE group_members DISABLE TRIGGER identity_directory_group_commit');
  try { await assert.rejects(remove(value), error => error.code === '55000'); }
  finally { await pool.query('ALTER TABLE group_members ENABLE TRIGGER identity_directory_group_commit'); }
  assert.deepEqual(await groupLinks(value.groups[0].id), before);
});

test('raw receipt update/delete/truncate, scope clearing and earlier or unrelated canonical effects are rejected', async () => {
  const value = await fixture(1);
  const earlier = wrapped({ query: async (client, sql, values, options) => {
    if (!options.readOnly && sql.startsWith('SELECT identity_company_offboarding_groups_begin')) await client.query('UPDATE groups SET name=name WHERE id=$1', [value.groups[0].id]);
    return client.query(sql, values);
  } });
  assert.equal((await remove(value, earlier)).results[0].status, 'unconfirmed'); assert.equal((await receipts()).length, 0);
  for (const mutation of [client => client.query("SELECT set_config('opendirectory.company_offboarding_groups','',true)"),
    client => client.query('UPDATE users SET title=$2 WHERE id=$1', [value.second.id, 'Unrelated effect'])]) {
    assert.equal((await remove(value, wrapped({ beforeCommit: mutation }))).results[0].status, 'unconfirmed'); assert.equal((await receipts()).length, 0);
  }
  await remove(value);
  for (const table of ['identity_company_offboarding_group_receipts', 'identity_company_offboarding_group_outbox']) {
    for (const statement of ['UPDATE ' + table + ' SET tenant_id=tenant_id', 'DELETE FROM ' + table, 'TRUNCATE ' + table + ' CASCADE'])
      await assert.rejects(pool.query(statement), error => error.code === '42501');
  }
  assert.equal((await receipts()).length, 1);
});

test('original external source withdrawal after child DML rolls back and withholds summary', async () => {
  const value = await fixture(); const live = {}; const observed = wrapped({ query: async (client, sql, values) => {
    const result = await client.query(sql, values); if (sql.startsWith('DELETE FROM group_members')) live.withdrawn = true; return result;
  } });
  await assert.rejects(remove(value, observed, settings(live)), error => error.status === 401);
  assert.equal((await receipts()).length, 0); assert.equal((await groupLinks(value.groups[0].id)).length, 2);
});

test('physical commit enforces original MFA deadline after application beforeCommit has completed', async () => {
  const value = await fixture(1); const authTime = Math.floor(Date.now() / 1000) - 295;
  value.actor.user = { ...value.actor.user, auth_time: authTime, mfa_authorization: { ...value.actor.user.mfa_authorization, authTime } };
  let physicalError;
  const observed = wrapped({ beforeCommit: async client => {
    await client.query("SET LOCAL statement_timeout='15s'");
    await client.query("SELECT pg_sleep(GREATEST(0,(current_setting('opendirectory.company_offboarding_groups')::jsonb->>'validUntil')::numeric-extract(epoch FROM clock_timestamp()))::double precision+0.1)");
  }, onError: error => { physicalError ||= error; } });
  await assert.rejects(remove(value, observed), error => [401, 428].includes(error.status));
  assert.equal(physicalError.code, '42501');
  assert.equal((await receipts()).length, 0); assert.equal((await groupLinks(value.groups[0].id)).length, 2);
});

test('actual PostgreSQL locks cover actor and target before the own group lock', async () => {
  const value = await fixture(1); const observer = await pool.connect(); let observed = false;
  const locked = async identifier => {
    await observer.query('BEGIN');
    try { await assert.rejects(observer.query('SELECT id FROM users WHERE id=$1 FOR UPDATE NOWAIT', [identifier]), error => error.code === '55P03'); }
    finally { await observer.query('ROLLBACK'); }
  };
  const wrapper = wrapped({ query: async (client, sql, values, options) => {
    if (!options.readOnly && !observed && sql.startsWith('SELECT id FROM groups') && sql.includes('FOR UPDATE')) {
      observed = true; await locked(value.actor.user.identity_authorization.userId); await locked(value.target.id);
      await observer.query('BEGIN'); await observer.query('SELECT id FROM groups WHERE id=$1 FOR UPDATE NOWAIT', [value.groups[0].id]); await observer.query('ROLLBACK');
      const result = await client.query(sql, values);
      await observer.query('BEGIN');
      try { await assert.rejects(observer.query('SELECT id FROM groups WHERE id=$1 FOR UPDATE NOWAIT', [value.groups[0].id]), error => error.code === '55P03'); }
      finally { await observer.query('ROLLBACK'); }
      return result;
    }
    return client.query(sql, values);
  } });
  try { assert.equal((await remove(value, wrapper)).results[0].status, 'removed'); assert.equal(observed, true); }
  finally { observer.release(); }
});

test('SQL rejects null or numeric reasons and nonstring token hashes in otherwise original retained source', async () => {
  const value = await fixture(1); await remove(value); const original = (await receipts())[0].source;
  for (const changed of [{ ...original, reason: null }, { ...original, reason: 1234567890 }, { ...original, tokenSha256: null }, { ...original, tokenSha256: 123 }])
    await assert.rejects(pool.query('SELECT identity_company_offboarding_groups_actor($1::jsonb)', [JSON.stringify(changed)]), error => error.code === '23514');
});

test('actual home admin still needs independent group permissions and cannot substitute missing fresh MFA or a workload', async () => {
  const value = await fixture(1); const original = value.actor.user;
  value.actor.user = { ...original, roles: [], permissions: ['groups.read'] };
  assert.equal((await service().preview(value.target.id, { workflowId: value.parent.workflowId }, value.actor.user, authorization)).total, 1);
  await assert.rejects(remove(value), error => error.status === 403);
  for (const changed of [{ ...original, actor_type: 'application' }, { ...original, mfa_authorization: undefined }, { ...original, auth_time: original.auth_time - 301 }]) {
    value.actor.user = changed; await assert.rejects(remove(value), error => [403, 428].includes(error.status));
  }
  assert.equal((await receipts()).length, 0);
});

test('an actual replacement membership before preflight cannot be adopted by the old manifest', async () => {
  const value = await fixture(); const member = value.intent.memberships[1]; let group = await loadGroup(member.groupId);
  group = await new GroupMutator(database, settings()).removeMember(group.id, value.target.id, groupEtag(group), value.actor.user, authorization);
  await new GroupMutator(database, settings()).add(group.id, { userId: value.target.id }, groupEtag(group), value.actor.user, authorization);
  let attempts = 0; const observed = wrapped({ query: async (client, sql, values) => { if (sql.startsWith('DELETE FROM group_members')) attempts++; return client.query(sql, values); } });
  await assert.rejects(remove(value, observed), error => error.status === 412); assert.equal(attempts, 0); assert.equal((await receipts()).length, 0);
});

test('source withdrawal after an earlier committed child withholds the summary while preserving that receipt', async () => {
  const value = await fixture(); const live = {};
  await assert.rejects(remove(value, wrapped({ afterCommit: async () => { live.withdrawn = true; } }), settings(live)), error => error.status === 401);
  assert.equal((await receipts()).length, 1); assert.equal((await groupLinks(value.intent.memberships[1].groupId)).length, 2);
});

test('SET ROLE fails the physical owner boundary and retained recovery cannot carry unrelated effects', async () => {
  const value = await fixture(1); const role = 'cleanup_role_' + randomUUID().replaceAll('-', '');
  await administration.query('CREATE ROLE ' + role + ' NOLOGIN');
  try {
    const result = await remove(value, wrapped({ beforeCommit: client => client.query('SET LOCAL ROLE ' + role) }));
    assert.equal(result.results[0].status, 'unconfirmed'); assert.equal(result.results[0].code, 403); assert.equal((await receipts()).length, 0);
  } finally { await administration.query('DROP ROLE ' + role); }
  await remove(value); const before = await receipts();
  const result = await remove(value, wrapped({ beforeCommit: client => client.query('UPDATE users SET title=$2 WHERE id=$1', [value.second.id, 'Forbidden recovery effect']) }));
  assert.equal(result.results[0].status, 'unconfirmed'); assert.deepEqual(await receipts(), before);
});

test('late receipt substitutions and raw evidence inserts cannot bypass immutable original child proof', async () => {
  const value = await fixture(1);
  for (const change of ["NEW.name='Forged retained name'", 'NEW.actor_user_id=gen_random_uuid()', "NEW.source=jsonb_set(NEW.source,'{reason}',to_jsonb('Forged late cleanup reason'::text))"]) {
    await pool.query('CREATE FUNCTION cleanup_substitute() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN ' + change + ';RETURN NEW;END $$;CREATE TRIGGER zz_cleanup_substitute BEFORE INSERT ON identity_company_offboarding_group_receipts FOR EACH ROW EXECUTE FUNCTION cleanup_substitute()');
    try { assert.equal((await remove(value)).results[0].status, 'unconfirmed'); }
    finally { await pool.query('DROP TRIGGER zz_cleanup_substitute ON identity_company_offboarding_group_receipts;DROP FUNCTION cleanup_substitute()'); }
    assert.equal((await receipts()).length, 0);
  }
  await remove(value);
  for (const table of ['identity_company_offboarding_group_receipts', 'identity_company_offboarding_group_outbox'])
    await assert.rejects(pool.query('INSERT INTO ' + table + ' SELECT * FROM ' + table), error => error.code === '42501');
});

test('missing parent pending outbox denies preview, history and writes before child effects', async () => {
  const value = await fixture(1);
  for (const trigger of ['identity_company_offboarding_guard', 'identity_company_offboarding_commit']) await pool.query('ALTER TABLE identity_company_offboarding_outbox DISABLE TRIGGER ' + trigger);
  try { await pool.query('DELETE FROM identity_company_offboarding_outbox'); }
  finally { for (const trigger of ['identity_company_offboarding_guard', 'identity_company_offboarding_commit']) await pool.query('ALTER TABLE identity_company_offboarding_outbox ENABLE TRIGGER ' + trigger); }
  for (const method of ['preview', 'history']) await assert.rejects(service()[method](value.target.id, { workflowId: value.parent.workflowId }, value.actor.user, authorization), error => error.code === '23514');
  await assert.rejects(remove(value), error => error.code === '23514'); assert.equal((await receipts()).length, 0);
});
