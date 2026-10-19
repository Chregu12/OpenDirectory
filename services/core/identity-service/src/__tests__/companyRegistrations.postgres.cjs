'use strict';

const { test, before, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { Pool } = require('pg');
const { CompanyRegistrations } = require('../CompanyRegistrations');
const { AuthorizationState } = require('../AuthorizationState');
const { CompanyRegistrationReviews } = require('../CompanyRegistrationReviews');
const { changeOperator } = require('../../scripts/company-review-operator');
const { PURPOSE, AUDIENCE, BASE_PATH } = require('../../../../../packages/company-registration-contract');
const { requestDigest } = require('../../../../../packages/company-registration-contract/digest');
const { provisionTenant, adoptTenant, enableTenant } = require('../../../../../scripts/lib/tenant-ownership-fixture.cjs');
const schema = 'company_registration_' + randomUUID().replaceAll('-', ''); const issuer = 'https://registration.test';
const migrations = path.join(__dirname, '../../migrations'); const administration = new Pool({ connectionString: process.env.IDENTITY_TEST_DATABASE_URL, max: 1 });
let pool; let database; let store; let beforeCommit;
const profile = { name: 'Verified request Company AG', legalForm: 'AG', registrationNumber: '', taxId: '', addressLine1: 'Business Street 1', addressLine2: '', postalCode: '8000', city: 'Zürich', country: 'CH', timezone: 'UTC', defaultLanguage: 'de', contactEmail: 'office@example.invalid', contactPhone: '', website: '' };
function input() { const subject = 'credential-' + randomUUID(); return { registrationId: randomUUID(), subject, principal: { username: subject, email: subject + '@example.invalid', displayName: 'Verified credential person' }, profile: { ...profile } }; }
function proof(value, operation = 'submit') { const now = Math.floor(Date.now() / 1000); return { iss: issuer, sub: 'oauth-provider', aud: AUDIENCE, token_use: PURPOSE, actor_type: 'workload', htm: 'POST', htu: BASE_PATH + '/' + operation,
  body_sha256: requestDigest(operation, value), registration_subject: value.subject, jti: randomUUID(), iat: now, exp: now + 30 }; }
const submit = value => store.receive('submit', value, proof(value));
const status = value => { const body = { registrationId: value.registrationId, subject: value.subject }; return store.receive('status', body, proof(body, 'status')); };
before(async () => {
  await administration.query('CREATE SCHEMA ' + schema); pool = new Pool({ connectionString: process.env.IDENTITY_TEST_DATABASE_URL, max: 8, options: `-c search_path=${schema},public` });
  database = { isAvailable: () => true, query: (...args) => pool.query(...args), getClient: () => pool.connect(), transaction: async (operation, options = {}) => {
    const client = await pool.connect();
    try { await client.query(options.readOnly ? 'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY' : 'BEGIN'); await client.query("SET LOCAL lock_timeout='4s';SET LOCAL statement_timeout='15s'"); if (options.actor) await client.query("SELECT set_config('opendirectory.actor',$1,true)", [options.actor]);
      const result = await operation(client); if (!options.readOnly && beforeCommit) await beforeCommit(client); await client.query('COMMIT'); return result;
    } catch (error) { await client.query('ROLLBACK'); throw error; } finally { client.release(); }
  } };
  for (const file of fs.readdirSync(migrations).filter(file => file.endsWith('.sql')).sort()) await pool.query(fs.readFileSync(path.join(migrations, file), 'utf8'));
  store = new CompanyRegistrations(database);
});
beforeEach(async () => { beforeCommit = null; await pool.query('TRUNCATE identity_tenants,users,groups,ous,identity_role_assignments,identity_pim_eligibilities,identity_role_review_policies CASCADE'); });
after(async () => { beforeCommit = null; await pool.end(); await administration.query('DROP SCHEMA ' + schema + ' CASCADE'); await administration.end(); });
async function counts() { return (await pool.query('SELECT (SELECT count(*)::int FROM identity_company_registrations) AS registrations,(SELECT count(*)::int FROM identity_company_registration_events) AS events,(SELECT count(*)::int FROM identity_company_registration_outbox) AS outbox,(SELECT count(*)::int FROM identity_tenants) AS tenants,(SELECT count(*)::int FROM users) AS users')).rows[0]; }
test('registration persists a real disabled tenant, canonical first-person candidate, exact verified subject and original pending event/outbox without granting authority', async () => {
  const value = input(); const receipt = await submit(value); assert.equal(receipt.status, 'pending-verification'); assert.equal(receipt.replayed, false); assert.equal(receipt.tenantEnabled, false); assert.equal(receipt.administratorEnabled, false); assert.equal(receipt.profileSaved, false); assert.equal(receipt.activationSupported, false);
  assert.deepEqual(await counts(), { registrations: 1, events: 1, outbox: 1, tenants: 1, users: 1 });
  const state = await new AuthorizationState(database).state(issuer, value.subject); assert.equal(state.active, false);
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_role_assignments')).rows[0].count, 0);
  const actual = (await pool.query('SELECT registration.*,event.type,event.version,event.correlation_id,outbox.status FROM identity_company_registrations registration JOIN identity_company_registration_events event ON event.id=registration.event_id JOIN identity_company_registration_outbox outbox ON outbox.id=event.id')).rows[0];
  assert.equal(actual.username, value.principal.username); assert.deepEqual(actual.profile, profile); assert.equal(actual.type, 'company.registration.requested'); assert.equal(actual.version, 1); assert.equal(actual.correlation_id, value.registrationId); assert.equal(actual.status, 'pending');
});
test('an exact repeated request and a fresh own status proof return the retained result without another tenant, user or event', async () => {
  const value = input(); const first = await submit(value); const repeated = await submit(value); assert.deepEqual(repeated, { ...first, replayed: true }); assert.deepEqual(await status(value), repeated);
  assert.deepEqual(await counts(), { registrations: 1, events: 1, outbox: 1, tenants: 1, users: 1 });
});
test('a registration key cannot change content, switch credential subject or create a second tenant for the same subject', async () => {
  const value = input(); await submit(value);
  await assert.rejects(submit({ ...value, profile: { ...profile, city: 'Other company' } }), error => error.status === 409);
  await assert.rejects(submit({ ...input(), registrationId: value.registrationId }), error => error.status === 409);
  await assert.rejects(submit({ ...value, registrationId: randomUUID() }), error => error.status === 409);
  await assert.rejects(status({ ...value, subject: 'another-credential' }), error => error.status === 404); assert.equal((await counts()).tenants, 1);
});
test('existing owned and unowned credential bindings are never silently adopted or rehomed by self-service registration', async () => {
  for (const owned of [false, true]) {
    const value = input(); const userId = randomUUID(); await pool.query('INSERT INTO users(id,username,email) VALUES($1,$2,$3)', [userId, value.principal.username, value.principal.email]);
    await pool.query('INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES($1,$2,$3)', [issuer, value.subject, userId]);
    if (owned) { const tenant = await provisionTenant(database, schema, { enabled: true }); await adoptTenant(database, schema, tenant, [{ kind: 'user', resourceId: userId }]); }
    await assert.rejects(submit(value), error => error.status === 409);
  }
  assert.equal((await counts()).registrations, 0);
});
test('actual parallel identical registrations wait on the same advisory lock and create only one canonical component', { timeout: 15000 }, async () => {
  const value = input(); let readySignal; let release; const ready = new Promise(resolve => { readySignal = resolve; }); const gate = new Promise(resolve => { release = resolve; }); let hold = true;
  beforeCommit = async () => { if (hold) { hold = false; readySignal(); await gate; } };
  const first = submit(value); await ready; const second = submit(value);
  try { let waiting = false; const until = Date.now() + 2500;
    while (Date.now() < until) { waiting = (await pool.query("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'SELECT identity_company_activation_admit%') AS waiting")).rows[0].waiting; if (waiting) break; await new Promise(resolve => setTimeout(resolve, 10)); } assert.equal(waiting, true);
  } finally { release(); }
  const results = await Promise.all([first, second]); assert.equal(results[0].tenantId, results[1].tenantId); assert.equal(results.filter(row => row.replayed).length, 1); beforeCommit = null; assert.equal((await counts()).tenants, 1);
});
test('a physically expired original issuer proof cannot commit even after the application has assembled a valid pending receipt', { timeout: 15000 }, async () => {
  const value = input(); const claims = proof(value); claims.exp = claims.iat + 2;
  beforeCommit = async () => { await new Promise(resolve => setTimeout(resolve, Math.max(0, claims.exp * 1000 - Date.now()) + 100)); };
  await assert.rejects(store.receive('submit', value, claims), error => error.status === 401); beforeCommit = null;
  assert.deepEqual(await counts(), { registrations: 0, events: 0, outbox: 0, tenants: 0, users: 0 });
});
test('missing exact receiving or deferred guards are unavailable before any partial registration write', async () => {
  for (const [table, trigger] of [['identity_company_registrations', 'identity_company_registration_commit'], ['identity_company_registration_outbox', 'identity_company_registration_guard'], ['users', 'aaa_identity_company_registration_fence']]) {
    await pool.query('ALTER TABLE ' + table + ' DISABLE TRIGGER ' + trigger);
    try { await assert.rejects(submit(input()), error => error.status === 503); } finally { await pool.query('ALTER TABLE ' + table + ' ENABLE TRIGGER ' + trigger); }
  }
  assert.equal((await counts()).tenants, 0);
});
test('an actually omitted registration outbox rolls back the entire tenant and canonical candidate', async () => {
  await pool.query('CREATE FUNCTION company_test_omit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$;CREATE TRIGGER zz_omit BEFORE INSERT ON identity_company_registration_outbox FOR EACH ROW EXECUTE FUNCTION company_test_omit()');
  try { await assert.rejects(submit(input()), error => error.status === 503); } finally { await pool.query('DROP TRIGGER zz_omit ON identity_company_registration_outbox;DROP FUNCTION company_test_omit()'); }
  assert.equal((await counts()).users, 0); assert.equal((await counts()).tenants, 0);
});
test('omitting actual canonical user eligibility or tenant outbox evidence cannot be replaced by a plausible registration snapshot', async () => {
  for (const table of ['identity_user_outbox', 'identity_tenant_outbox']) {
    await pool.query('CREATE FUNCTION company_test_omit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$;CREATE TRIGGER zz_omit BEFORE INSERT ON ' + table + ' FOR EACH ROW EXECUTE FUNCTION company_test_omit()');
    try { await assert.rejects(submit(input()), error => error.status === 503); } finally { await pool.query('DROP TRIGGER zz_omit ON ' + table + ';DROP FUNCTION company_test_omit()'); }
    assert.equal((await counts()).registrations, 0); assert.equal((await counts()).users, 0);
  }
});
test('a late user trigger cannot turn the first candidate into an enabled user behind initial registration validation', async () => {
  await pool.query('CREATE FUNCTION company_test_enable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN NEW.enabled=true; RETURN NEW; END $$;CREATE TRIGGER zz_enable BEFORE INSERT ON users FOR EACH ROW EXECUTE FUNCTION company_test_enable()');
  try { await assert.rejects(submit(input()), error => error.status === 503); } finally { await pool.query('DROP TRIGGER zz_enable ON users;DROP FUNCTION company_test_enable()'); }
  assert.equal((await counts()).tenants, 0); assert.equal((await counts()).users, 0);
});
test('a cleared scope cannot hide extra canonical writes or truncation after the actual registration event', async () => {
  for (const statement of ["INSERT INTO groups(id,name) VALUES(gen_random_uuid(),'Unrelated')", 'TRUNCATE identity_company_registration_outbox']) {
    beforeCommit = async client => { await client.query("SELECT set_config('opendirectory.company_registration','',true)"); await client.query(statement); };
    await assert.rejects(submit(input()), error => error.status === 503); beforeCommit = null; assert.equal((await counts()).tenants, 0);
  }
});
test('raw writes cannot rewrite immutable registration evidence and missing retained outbox evidence never produces a later success', async () => {
  const value = input(); await submit(value);
  for (const statement of ["UPDATE identity_company_registrations SET subject='another-person'", 'DELETE FROM identity_company_registration_events']) await assert.rejects(pool.query(statement), error => error.code === '42501');
  await pool.query('ALTER TABLE identity_company_registration_outbox DISABLE TRIGGER identity_company_registration_guard');
  try { await pool.query('DELETE FROM identity_company_registration_outbox'); } finally { await pool.query('ALTER TABLE identity_company_registration_outbox ENABLE TRIGGER identity_company_registration_guard'); }
  await assert.rejects(status(value), error => error.status === 503); await assert.rejects(submit(value), error => error.status === 503);
});
test('an actual limited SQL login or SET ROLE cannot launder a captured registration proof through a granted security definer', async () => {
  const role = 'company_limited_' + randomUUID().replaceAll('-', ''); const value = input(); const claims = proof(value); let limited;
  const descriptor = { issuer, subject: value.subject, nonce: claims.jti, issuedAt: claims.iat, expiresAt: claims.exp, requestSha256: claims.body_sha256 };
  await administration.query('CREATE ROLE ' + role + ' LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS');
  try {
    await pool.query('GRANT USAGE ON SCHEMA ' + schema + ' TO ' + role + ';GRANT EXECUTE ON FUNCTION identity_company_registration_submit(jsonb,jsonb) TO ' + role);
    const address = new URL(process.env.IDENTITY_TEST_DATABASE_URL); address.username = role; limited = new Pool({ connectionString: address.toString(), options: `-c search_path=${schema},public`, max: 1 });
    for (const assumed of [false, true]) { const client = await (assumed ? pool : limited).connect();
      try { await client.query('BEGIN'); if (assumed) await client.query('SET LOCAL ROLE ' + role);
        await assert.rejects(client.query('SELECT identity_company_registration_submit($1::jsonb,$2::jsonb)', [JSON.stringify(descriptor), JSON.stringify(value)]), error => error.code === '42501' && error.message.includes('Actual database owner required'));
      } finally { await client.query('ROLLBACK'); client.release(); }
    }
  } finally { await limited?.end(); await pool.query('DROP OWNED BY ' + role); await administration.query('DROP ROLE ' + role); }
  assert.equal((await counts()).registrations, 0);
});
test('SQL replay and caller time zones preserve original pending receipts and the 62-role catalog without activating the new company', async () => {
  const value = input(); const first = await submit(value); await pool.query(fs.readFileSync(path.join(migrations, '039_company_registrations.sql'), 'utf8')); await pool.query("SET timezone='Pacific/Honolulu'");
  assert.deepEqual(await status(value), { ...first, replayed: true }); assert.equal((await pool.query("SELECT jsonb_array_length(identity_authority_catalog()->'roles') AS count")).rows[0].count, 62);
  for (const file of fs.readdirSync(migrations).filter(file => file.endsWith('.sql') && file > '039_company_registrations.sql').sort()) await pool.query(fs.readFileSync(path.join(migrations, file), 'utf8'));
});
test('an independently changed canonical tenant cannot be advertised as a still-matching pending registration or silently repaired by a retry', async () => {
  const value = input(); const receipt = await submit(value); await enableTenant(database, schema, receipt.tenantId, true);
  await assert.rejects(status(value), error => error.status === 503); await assert.rejects(submit(value), error => error.status === 503); assert.equal((await counts()).tenants, 1);
});
async function reviewer(enabled = true) {
  const tenant = await provisionTenant(database, schema, { enabled: true }); const id = randomUUID(); const subject = 'reviewer-' + id;
  await pool.query('INSERT INTO users(id,username,email) VALUES($1,$2,$3)', [id, subject, subject + '@example.invalid']);
  await pool.query('INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES($1,$2,$3)', [issuer, subject, id]);
  await adoptTenant(database, schema, tenant, [{ kind: 'user', resourceId: id }]);
  if (enabled) await changeOperator(database, { issuer, userId: id, version: '0', enabled: true, reason: 'Explicit platform company reviewer fixture' });
  const state = await new AuthorizationState(database).state(issuer, subject); const authTime = Math.floor(Date.now() / 1000);
  return { iss: issuer, sub: subject, actor_type: 'user', roles: state.roles, identity_authorization: state.context, jti: randomUUID(), exp: authTime + 300,
    auth_time: authTime, amr: ['pwd', 'otp'], mfa_authorization: { schemaVersion: 1, userId: id, revision: '1', authTime, methods: ['pwd', 'otp'] } };
}
const reviewBody = { decision: 'approved', reason: 'Company evidence independently reviewed', confirm: true };
const reviewStore = revalidate => new CompanyRegistrationReviews(database, { revalidate: revalidate || (async () => {}) });
test('explicit platform reviewer approves a real request with original checkpoint and immutable audit but no tenant, user or role activation', async () => {
  const value = input(); const pending = await submit(value); const user = await reviewer(); const reviews = reviewStore(); const before = await reviews.get(value.registrationId, user);
  assert.deepEqual(await reviews.permissions(user), ['company.registrations.review']); const result = await reviews.decide(value.registrationId, reviewBody, before.etag, user, 'Bearer original');
  assert.equal(result.status, 'pending-activation'); assert.equal(result.canReview, false); assert.equal(result.review.reviewerUserId, user.identity_authorization.userId);
  const receipt = await status(value); assert.equal(receipt.schemaVersion, 2); assert.equal(receipt.status, 'pending-activation'); assert.equal(receipt.tenantEnabled, false); assert.equal(receipt.administratorEnabled, false); assert.equal(receipt.activationSupported, false);
  assert.deepEqual(await submit(value), receipt); assert.equal(receipt.tenantId, pending.tenantId); assert.equal((await new AuthorizationState(database).state(issuer, value.subject)).active, false);
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_role_assignments')).rows[0].count, 0);
  const checkpoint = (await pool.query('SELECT * FROM identity_authority_command_checkpoints')).rows[0]; assert.notEqual(checkpoint.tenant_id, receipt.tenantId); assert.equal(checkpoint.user_id, user.identity_authorization.userId);
});
test('registration rejection is real, final and privately exposes no reviewer reason to the applicant', async () => {
  const value = input(); await submit(value); const user = await reviewer(); const reviews = reviewStore(); const before = await reviews.get(value.registrationId, user);
  const result = await reviews.decide(value.registrationId, { ...reviewBody, decision: 'rejected' }, before.etag, user, 'Bearer original'); assert.equal(result.status, 'rejected');
  const receipt = await status(value); assert.equal(receipt.status, 'rejected'); assert.equal(Object.hasOwn(receipt, 'reason'), false); assert.equal(Object.hasOwn(receipt, 'reviewerUserId'), false);
  await assert.rejects(reviews.decide(value.registrationId, reviewBody, before.etag, user, 'Bearer original'), error => error.status === 412);
  await assert.rejects(reviews.decide(value.registrationId, reviewBody, result.etag, user, 'Bearer original'), error => error.status === 409);
});
test('global admin, claimed permission and workloads have no implicit platform company review authority', async () => {
  const value = input(); await submit(value); const user = await reviewer(false); const reviews = reviewStore();
  for (const actor of [user, { ...user, roles: ['admin'], permissions: ['company.registrations.review'] }, { ...user, actor_type: 'application' }]) {
    assert.deepEqual(await reviews.permissions(actor), []); await assert.rejects(reviews.get(value.registrationId, actor), error => error.status === 403);
  }
});
test('review listing paginates and filters real decisions and rejects tenant selectors', async () => {
  const first = input(); const second = input(); await submit(first); await submit(second); const user = await reviewer(); const reviews = reviewStore();
  const page = await reviews.list({ limit: '1' }, user); assert.equal(page.total, 2); assert.equal(page.registrations.length, 1);
  const next = await reviews.list({ limit: '1', page: '2' }, user); assert.notEqual(next.registrations[0].registrationId, page.registrations[0].registrationId);
  const detail = await reviews.get(first.registrationId, user); await reviews.decide(first.registrationId, reviewBody, detail.etag, user, 'Bearer original');
  assert.equal((await reviews.list({}, user)).total, 1); assert.equal((await reviews.list({ status: 'pending-activation' }, user)).total, 1);
  for (const query of [{ tenantId: randomUUID() }, { page: '0' }, { limit: '51' }, { page: ['1'] }, { status: 'invented' }]) await assert.rejects(reviews.list(query, user), error => error.status === 400);
});
test('fresh MFA is required even for cross-tenant review reads and missing version or confirmation never writes', async () => {
  const value = input(); await submit(value); const user = await reviewer(); const reviews = reviewStore(); const before = await reviews.get(value.registrationId, user);
  const stale = structuredClone(user); stale.auth_time -= 301; stale.mfa_authorization.authTime -= 301;
  await assert.rejects(reviews.get(value.registrationId, stale), error => error.status === 428); await assert.rejects(reviews.decide(value.registrationId, reviewBody, before.etag, stale, 'Bearer original'), error => error.status === 428);
  await assert.rejects(reviews.decide(value.registrationId, reviewBody, '', user, 'Bearer original'), error => error.status === 428);
  for (const body of [{ ...reviewBody, confirm: false }, { ...reviewBody, tenantId: randomUUID() }]) await assert.rejects(reviews.decide(value.registrationId, body, before.etag, user, 'Bearer original'), error => error.status === 400);
});
test('offline reviewer revocation invalidates old context immediately while retained historical review remains valid', async () => {
  const value = input(); await submit(value); const user = await reviewer(); const reviews = reviewStore(); const before = await reviews.get(value.registrationId, user);
  await reviews.decide(value.registrationId, reviewBody, before.etag, user, 'Bearer original'); const receipt = await status(value);
  await changeOperator(database, { issuer, userId: user.identity_authorization.userId, version: '1', enabled: false, reason: 'Platform review duty explicitly withdrawn' });
  await assert.rejects(reviews.get(value.registrationId, user), error => [401, 403].includes(error.status)); assert.deepEqual(await status(value), receipt);
  await assert.rejects(changeOperator(database, { issuer, userId: user.identity_authorization.userId, version: '1', enabled: true, reason: 'Stale operator version is not accepted' }), error => error.code === '40001');
});
test('post-DML issuer withdrawal and physical original MFA expiry roll decision and outbox back', async () => {
  const value = input(); await submit(value); const user = await reviewer(); let checks = 0; const reviews = reviewStore(async () => { if (++checks === 2) throw Object.assign(new Error('original withdrawn'), { status: 401 }); }); const before = await reviews.get(value.registrationId, user);
  await assert.rejects(reviews.decide(value.registrationId, reviewBody, before.etag, user, 'Bearer original'), error => error.status === 401); assert.equal((await status(value)).status, 'pending-verification');
  user.auth_time -= 298; user.mfa_authorization.authTime -= 298; beforeCommit = client => client.query('SELECT pg_sleep(2.1)');
  await assert.rejects(reviewStore().decide(value.registrationId, reviewBody, before.etag, user, 'Bearer original'), error => error.status === 401); beforeCommit = null; assert.equal((await status(value)).status, 'pending-verification');
});
test('missing receiving guards, omitted outbox and scope clearing cannot produce a successful review', async () => {
  const value = input(); await submit(value); const user = await reviewer(); const reviews = reviewStore(); const before = await reviews.get(value.registrationId, user);
  for (const [table, trigger] of [['identity_company_review_events', 'identity_company_review_commit'], ['identity_company_review_outbox', 'identity_company_review_guard'], ['users', 'aaa_identity_company_review_no_effects']]) {
    await pool.query('ALTER TABLE ' + table + ' DISABLE TRIGGER ' + trigger);
    try { await assert.rejects(reviews.decide(value.registrationId, reviewBody, before.etag, user, 'Bearer original'), error => error.status === 503); } finally { await pool.query('ALTER TABLE ' + table + ' ENABLE TRIGGER ' + trigger); }
  }
  await pool.query('CREATE FUNCTION company_review_omit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL;END $$;CREATE TRIGGER zz_omit BEFORE INSERT ON identity_company_review_outbox FOR EACH ROW EXECUTE FUNCTION company_review_omit()');
  try { await assert.rejects(reviews.decide(value.registrationId, reviewBody, before.etag, user, 'Bearer original'), error => error.status === 503); } finally { await pool.query('DROP TRIGGER zz_omit ON identity_company_review_outbox;DROP FUNCTION company_review_omit()'); }
  for (const sql of ["INSERT INTO groups(id,name) VALUES(gen_random_uuid(),'Unrelated review')", 'TRUNCATE identity_company_review_outbox']) {
    beforeCommit = async client => { await client.query("SELECT set_config('opendirectory.company_review','',true)"); await client.query(sql); };
    await assert.rejects(reviews.decide(value.registrationId, reviewBody, before.etag, user, 'Bearer original'), error => error.status === 503); beforeCommit = null;
  }
  assert.equal((await status(value)).status, 'pending-verification');
});
test('actual concurrent independent reviews serialize and cannot overwrite the first final decision', { timeout: 15000 }, async () => {
  const value = input(); await submit(value); const first = await reviewer(); const second = await reviewer(); const reviews = reviewStore(); const before = await reviews.get(value.registrationId, first);
  let readySignal; let release; const ready = new Promise(resolve => { readySignal = resolve; }); const gate = new Promise(resolve => { release = resolve; }); let hold = true;
  beforeCommit = async () => { if (hold) { hold = false; readySignal(); await gate; } };
  const winner = reviews.decide(value.registrationId, reviewBody, before.etag, first, 'Bearer first'); await ready;
  const loser = reviews.decide(value.registrationId, { ...reviewBody, decision: 'rejected' }, before.etag, second, 'Bearer second'); const rejected = assert.rejects(loser, error => error.status === 412);
  try { let waiting = false; const until = Date.now() + 2500;
    while (Date.now() < until) { waiting = (await pool.query("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'SELECT identity_company_review_decide%') AS waiting")).rows[0].waiting; if (waiting) break; await new Promise(resolve => setTimeout(resolve, 10)); } assert.equal(waiting, true);
  } finally { release(); }
  await winner; await rejected; beforeCommit = null; assert.equal((await status(value)).status, 'pending-activation');
});
test('review SQL replay preserves decisions and missing retained review evidence fails closed for the applicant', async () => {
  const value = input(); await submit(value); const user = await reviewer(); const reviews = reviewStore(); const before = await reviews.get(value.registrationId, user);
  await reviews.decide(value.registrationId, reviewBody, before.etag, user, 'Bearer original'); const receipt = await status(value);
  await pool.query(fs.readFileSync(path.join(migrations, '040_company_registration_reviews.sql'), 'utf8')); assert.deepEqual(await status(value), receipt);
  for (const sql of ["UPDATE identity_company_registration_reviews SET decision='rejected'", 'DELETE FROM identity_company_review_events', 'UPDATE identity_company_review_operators SET enabled=false']) await assert.rejects(pool.query(sql), error => error.code === '42501');
  await pool.query('ALTER TABLE identity_company_review_outbox DISABLE TRIGGER identity_company_review_guard');
  try { await pool.query("DELETE FROM identity_company_review_outbox WHERE id IN(SELECT id FROM identity_company_review_events WHERE kind='decision')"); } finally { await pool.query('ALTER TABLE identity_company_review_outbox ENABLE TRIGGER identity_company_review_guard'); }
  await assert.rejects(status(value), error => error.status === 503);
});
const activate = value => { const body = { registrationId: value.registrationId, subject: value.subject, consoleClientId: 'web-app' }; return store.receive('activate', body, proof(body, 'activate')); };
async function approvedRegistration() {
  const value = input(); await submit(value); const user = await reviewer(); const reviews = reviewStore(); const before = await reviews.get(value.registrationId, user);
  await reviews.decide(value.registrationId, reviewBody, before.etag, user, 'Bearer original'); return value;
}
async function activeCompany() {
  const value = await approvedRegistration(); const receipt = await activate(value); const state = await new AuthorizationState(database).state(issuer, value.subject); const authTime = Math.floor(Date.now() / 1000);
  return { value, receipt, user: { iss: issuer, sub: value.subject, actor_type: 'user', roles: state.roles, identity_authorization: state.context, jti: randomUUID(), exp: authTime + 300,
    auth_time: authTime, amr: ['pwd', 'otp'], mfa_authorization: { schemaVersion: 1, userId: receipt.administratorId, revision: '1', authTime, methods: ['pwd', 'otp'] } } };
}
function ownDirectory(options = {}) {
  const settings = { issuer, revalidate: async (_authorization, actor) => {
    const state = await new AuthorizationState(database).state(actor.iss, actor.sub);
    if (!state.active) throw Object.assign(new Error('Actual original actor no longer active'), { status: 401 }); return state.tenant;
  }, ...options };
  return { reader: new (require('../DirectoryReader').DirectoryReader)(database, settings), creator: new (require('../DirectoryCreator').DirectoryCreator)(database, settings), ous: new (require('../OuMutator').OuMutator)(database, settings),
    users: new (require('../UserMutator').UserMutator)(database, settings), groups: new (require('../GroupMutator').GroupMutator)(database, settings) };
}
function inventoryAuthority() {
  return new(require('../DeviceInventoryAuthority').DeviceInventoryAuthority)(database,{issuer,revalidate:async(_bearer,actor)=>{
    const current=await new AuthorizationState(database).state(actor.iss,actor.sub);if(!current.active)throw Object.assign(new Error('Actual inventory source inactive'),{status:401});return current.tenant;
  }});
}
test('actual roleless company owner supplies bounded live inventory authority and only own canonical recipient snapshots',async()=>{
  const first=await activeCompany();const second=await activeCompany();const bearer='Bearer actual-original-owner';const authority=inventoryAuthority();
  const employee=await ownDirectory().creator.user({username:'inventory-employee',email:'inventory@example.invalid'},first.user,bearer);
  const source=await authority.read(first.user,bearer,{userId:employee.id});assert.deepEqual(source.permissions,require('../../../../../packages/device-inventory-contract').INVENTORY_PERMISSIONS);assert.equal(source.tenant.id,first.receipt.tenantId);assert.equal(source.actorUserId,first.receipt.administratorId);assert.deepEqual(source.target,{id:employee.id,revision:String((await pool.query('SELECT authorization_revision FROM users WHERE id=$1',[employee.id])).rows[0].authorization_revision),enabled:false});assert.deepEqual(first.user.roles,[]);
  await assert.rejects(authority.read(first.user,bearer,{userId:second.receipt.administratorId}),error=>error.status===404);
  await assert.rejects(authority.read({...first.user,auth_time:first.user.auth_time-301},bearer),error=>error.status===428);
});
test('withdrawing the actual company owner link invalidates its live inventory source despite retained activation evidence',async()=>{
  const company=await activeCompany();const authority=inventoryAuthority();await authority.read(company.user,'Bearer original');
  await pool.query('DELETE FROM identity_subject_links WHERE issuer=$1 AND subject=$2',[issuer,company.user.sub]);
  await assert.rejects(authority.read(company.user,'Bearer original'),error=>error.status===401);
});
test('a roleless company owner creates a real own hierarchy, employees and group, with versioned mutations and mandatory receipts', async () => {
  const { user, receipt } = await activeCompany(); const { reader, creator, users, groups } = ownDirectory(); const bearer = 'Bearer native-original-owner';
  const root = await creator.ou({ name: 'Engineering' }, user, bearer); const child = await creator.ou({ name: 'Platform', parentId: root.id }, user, bearer);
  const first = await creator.user({ username: 'employee-one', email: 'one@example.invalid', displayName: 'First Employee' }, user, bearer);
  const second = await creator.user({ username: 'employee-two', email: 'two@example.invalid' }, user, bearer); assert.equal(first.enabled, false); assert.equal(second.enabled, false);
  const tree = await reader.ous({}, user, bearer); assert.equal(tree.total, 2); assert.equal(tree.tree[0].children[0].id, child.id);
  const { userEtag } = require('../DirectoryUsers'); const { groupEtag } = require('../GroupMutator');
  const updated = await users.update(first.id, { department: 'Engineering' }, userEtag(first), user, bearer); assert.equal(updated.department, 'Engineering');
  await assert.rejects(users.update(first.id, { title: 'Stale write' }, userEtag(first), user, bearer), error => error.status === 412);
  const enabled = await users.update(first.id, { enabled: true }, userEtag(updated), user, bearer); assert.equal(enabled.enabled, true);
  let group = await creator.group({ name: 'Engineering Team' }, user, bearer); group = await groups.update(group.id, { description: 'Own actual employees' }, groupEtag(group), user, bearer);
  group = await groups.add(group.id, { userId: first.id }, groupEtag(group), user, bearer); assert.deepEqual(group.members, [first.id]);
  group = await groups.removeMember(group.id, first.id, groupEtag(group), user, bearer); assert.deepEqual(group.members, []); await groups.remove(group.id, groupEtag(group), user, bearer);
  assert.deepEqual((await reader.groups({}, user, bearer)).groups, []); assert.equal((await reader.users({}, user, bearer)).total, 3);
  const actual = (await pool.query(`SELECT
    (SELECT count(*)::int FROM identity_tenant_events event JOIN identity_tenant_outbox outbox USING(id) WHERE event.tenant_id=$1 AND event.action='resource-created') AS creations,
    (SELECT count(*)::int FROM identity_directory_user_events event JOIN identity_directory_user_outbox outbox USING(id) WHERE event.tenant_id=$1) AS user_mutations,
    (SELECT count(*)::int FROM identity_directory_group_events event JOIN identity_directory_group_outbox outbox USING(id) WHERE event.tenant_id=$1) AS group_mutations,
    (SELECT count(*)::int FROM identity_role_assignments WHERE user_id=ANY($2::uuid[])) AS grants,
    (SELECT count(*)::int FROM identity_subject_links WHERE user_id=ANY($3::uuid[])) AS employee_logins`, [receipt.tenantId, [user.identity_authorization.userId, first.id, second.id], [first.id, second.id]])).rows[0];
  assert.deepEqual(actual, { creations: 5, user_mutations: 2, group_mutations: 4, grants: 0, employee_logins: 0 });
});
test('actual different companies cannot enumerate, read, overwrite or link each other through the owner directory path', async () => {
  const first = await activeCompany(); const second = await activeCompany(); const { reader, creator, users, groups } = ownDirectory(); const bearer = 'Bearer original-own-company';
  const foreignUser = await creator.user({ username: 'foreign-employee', email: 'foreign@example.invalid' }, second.user, bearer);
  const foreignGroup = await creator.group({ name: 'Foreign private group' }, second.user, bearer); const foreignOu = await creator.ou({ name: 'Foreign private unit' }, second.user, bearer);
  const ownGroup = await creator.group({ name: 'Own group' }, first.user, bearer);
  assert.deepEqual((await reader.users({}, first.user, bearer)).users.map(account => account.id), [first.receipt.administratorId]);
  for (const [method, id] of [['user', foreignUser.id], ['group', foreignGroup.id], ['ou', foreignOu.id]]) await assert.rejects(reader[method](id, {}, first.user, bearer), error => error.status === 404);
  await assert.rejects(users.update(foreignUser.id, { displayName: 'Forbidden' }, require('../DirectoryUsers').userEtag(foreignUser), first.user, bearer), error => error.status === 404);
  await assert.rejects(groups.update(foreignGroup.id, { name: 'Forbidden' }, require('../GroupMutator').groupEtag(foreignGroup), first.user, bearer), error => error.status === 404);
  await assert.rejects(groups.add(ownGroup.id, { userId: foreignUser.id }, require('../GroupMutator').groupEtag(ownGroup), first.user, bearer), error => error.status === 404);
  await assert.rejects(creator.ou({ name: 'No foreign parent', parentId: foreignOu.id }, first.user, bearer), error => error.status === 404);
  assert.deepEqual((await reader.groups({}, second.user, bearer)).groups.map(group => group.id), [foreignGroup.id]);
});
test('an actual roleless company owner edits, moves and retires only its own units without a global grant', async () => {
  const first = await activeCompany(); const second = await activeCompany(); const { creator, reader, ous } = ownDirectory(); const { ouEtag } = require('../OuMutator');
  const root = await creator.ou({ name: 'Company root' }, first.user, 'Bearer original'); const child = await creator.ou({ name: 'Company child', parentId: root.id }, first.user, 'Bearer original'); const foreign = await creator.ou({ name: 'Foreign root' }, second.user, 'Bearer other');
  const moved = await ous.update(child.id, { name: 'Independent company unit', parentId: null }, ouEtag(child), first.user, 'Bearer original'); assert.equal(moved.parentId, undefined); assert.equal(moved.name, 'Independent company unit');
  await assert.rejects(ous.update(foreign.id, { name: 'Forbidden' }, ouEtag(foreign), first.user, 'Bearer original'), error => error.status === 404); await assert.rejects(ous.remove(foreign.id, ouEtag(foreign), first.user, 'Bearer original'), error => error.status === 404);
  await ous.remove(root.id, ouEtag(root), first.user, 'Bearer original'); assert.equal((await reader.ous({}, first.user, 'Bearer original')).total, 1); assert.deepEqual(first.user.roles, []);
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_directory_ou_events WHERE tenant_id=$1', [first.receipt.tenantId])).rows[0].count, 2);
});
test('the actual roleless company owner assigns disabled employees to multiple own units and removes only the requested link', async () => {
  const company = await activeCompany(); const { creator, reader, ous } = ownDirectory(); const first = await creator.ou({ name: 'Engineering' }, company.user, 'Bearer original'); const second = await creator.ou({ name: 'Operations' }, company.user, 'Bearer original');
  const employee = await creator.user({ username: 'own-ou-employee', email: 'employee@example.invalid', displayName: 'Actual Company Employee' }, company.user, 'Bearer original'); const { ouEtag } = require('../OuMutator');
  const firstLink = await ous.addMember(first.id, { userId: employee.id }, ouEtag(first), company.user, 'Bearer original'); await ous.addMember(second.id, { userId: employee.id }, ouEtag(second), company.user, 'Bearer original');
  const firstPage = await reader.ouMembers(first.id, {}, company.user, 'Bearer original'); assert.equal(firstPage.profileAccess, true); assert.equal(firstPage.members[0].profile.displayName, employee.displayName);
  await ous.removeMember(first.id, firstLink.membership.id, ouEtag(firstLink.unit), company.user, 'Bearer original'); assert.equal((await reader.ouMembers(first.id, {}, company.user, 'Bearer original')).total, 0); assert.equal((await reader.ouMembers(second.id, {}, company.user, 'Bearer original')).total, 1);
  assert.deepEqual(company.user.roles, []); assert.equal((await reader.user(employee.id, {}, company.user, 'Bearer original')).enabled, false); assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_role_assignments WHERE user_id=$1', [employee.id])).rows[0].count, 0);
});
test('fresh MFA and invented company claims without a retained actual owner cannot grant directory access', async () => {
  const actor = { ...await reviewer(false), companyOwner: true, company_permissions: require('../CompanyOwner').COMPANY_DIRECTORY_PERMISSIONS }; const { reader, creator } = ownDirectory();
  for (const method of ['users', 'groups', 'ous']) await assert.rejects(reader[method]({}, actor, 'Bearer real-ordinary-user'), error => error.status === 403);
  await assert.rejects(creator.user({ username: 'not-created', email: 'not-created@example.invalid' }, actor, 'Bearer real-ordinary-user'), error => error.status === 403);
  assert.equal((await counts()).users, 1);
});
test('original bearer rejection after actual owner creation DML rolls back resource, ownership, event and outbox together', async () => {
  const { user } = await activeCompany(); let attempts = 0;
  const { creator } = ownDirectory({ revalidate: async () => { if (++attempts === 3) throw Object.assign(new Error('Original issuer rejected bearer after DML'), { status: 401 }); return (await new AuthorizationState(database).state(issuer, user.sub)).tenant; } });
  const before = (await pool.query('SELECT count(*)::int AS count FROM identity_tenant_events')).rows[0].count;
  await assert.rejects(creator.user({ username: 'rolled-back-employee', email: 'rollback@example.invalid' }, user, 'Bearer original'), error => error.status === 401);
  assert.equal(attempts, 3); assert.equal((await pool.query("SELECT count(*)::int AS count FROM users WHERE username='rolled-back-employee'")).rows[0].count, 0);
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_tenant_events')).rows[0].count, before);
});
test('physical original MFA or token expiry at deferred SQL commit rejects an otherwise valid owner creation', { timeout: 15000 }, async () => {
  const { user } = await activeCompany(); const { creator } = ownDirectory(); const expiring = { ...user, exp: Math.floor(Date.now() / 1000) + 2 };
  beforeCommit = async () => { await new Promise(resolve => setTimeout(resolve, 2200)); };
  await assert.rejects(creator.group({ name: 'Expired original owner group' }, expiring, 'Bearer expiring-original'), error => error.code === '42501'); beforeCommit = null;
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM groups')).rows[0].count, 0);
});
test('unlinking the actual owner identity removes directory access while retaining activation history', async () => {
  const { user, value } = await activeCompany(); const { reader } = ownDirectory(); assert.equal((await reader.users({}, user, 'Bearer original')).total, 1);
  await pool.query('DELETE FROM identity_subject_links WHERE issuer=$1 AND subject=$2', [issuer, user.sub]);
  await assert.rejects(reader.users({}, user, 'Bearer original'), error => error.status === 401); assert.equal((await status(value)).status, 'suspended');
});
test('actual OU creation preserves the supported depth boundary and refuses a pre-existing cyclic parent without a new namespace', async () => {
  const { user, receipt } = await activeCompany(); const { creator, reader } = ownDirectory(); const units = Array.from({ length: 256 }, (_, index) => ({ id: randomUUID(), name: 'Existing unit ' + index }));
  await pool.query("INSERT INTO ous(id,name) SELECT (unit->>'id')::uuid,unit->>'name' FROM jsonb_array_elements($1::jsonb) unit", [JSON.stringify(units)]);
  await adoptTenant(database, schema, receipt.tenantId, units.map(unit => ({ kind: 'ou', resourceId: unit.id })));
  const links = units.slice(1).map((unit, index) => ({ id: unit.id, parent: units[index].id }));
  await pool.query("UPDATE ous SET parent_id=(link->>'parent')::uuid FROM jsonb_array_elements($1::jsonb) link WHERE ous.id=(link->>'id')::uuid", [JSON.stringify(links)]);
  const permitted = await creator.ou({ name: 'Permitted level 256', parentId: units[254].id }, user, 'Bearer actual-owner'); assert.equal(permitted.parentId, units[254].id);
  const before = (await pool.query('SELECT count(*)::int AS count FROM identity_tenant_ownership')).rows[0].count;
  await assert.rejects(creator.ou({ name: 'Rejected level 257', parentId: units[255].id }, user, 'Bearer actual-owner'), error => error.status === 409);
  assert.equal((await reader.ous({}, user, 'Bearer actual-owner')).total, 257);
  await pool.query('UPDATE ous SET parent_id=$2 WHERE id=$1', [units[0].id, units[1].id]);
  await assert.rejects(creator.ou({ name: 'Rejected cyclic parent', parentId: units[1].id }, user, 'Bearer actual-owner'), error => error.status === 503);
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_tenant_ownership')).rows[0].count, before);
});
test('actual ancestor share locks retain the checked hierarchy until child creation physically commits', { timeout: 15000 }, async () => {
  const { user } = await activeCompany(); const { creator } = ownDirectory(); const root = await creator.ou({ name: 'Locked root' }, user, 'Bearer actual-owner'); const parent = await creator.ou({ name: 'Locked parent', parentId: root.id }, user, 'Bearer actual-owner');
  let readySignal; let release; const ready = new Promise(resolve => { readySignal = resolve; }); const gate = new Promise(resolve => { release = resolve; }); let held = true;
  beforeCommit = async () => { if (held) { held = false; readySignal(); await gate; } };
  const creating = creator.ou({ name: 'Actual protected child', parentId: parent.id }, user, 'Bearer actual-owner'); await ready;
  const concurrent = await pool.connect(); const pid = (await concurrent.query('SELECT pg_backend_pid() AS pid')).rows[0].pid; const changing = concurrent.query('UPDATE ous SET name=$1 WHERE id=$2', ['Changed after child commit', root.id]);
  try {
    let blocked = false; const until = Date.now() + 2000;
    while (Date.now() < until) { blocked = (await pool.query("SELECT wait_event_type='Lock' AS blocked FROM pg_stat_activity WHERE pid=$1", [pid])).rows[0]?.blocked; if (blocked) break; await new Promise(resolve => setTimeout(resolve, 10)); }
    assert.equal(blocked, true);
  } finally { release(); await creating; await changing; concurrent.release(); beforeCommit = null; }
  assert.equal((await pool.query('SELECT name FROM ous WHERE id=$1', [root.id])).rows[0].name, 'Changed after child commit');
});
test('the independently approved credential subject activates its own company, original profile and durable owner without any global role', async () => {
  const value = await approvedRegistration(); const receipt = await activate(value); assert.equal(receipt.schemaVersion, 3); assert.equal(receipt.status, 'active'); assert.equal(receipt.profileSaved, true); assert.equal(receipt.mfaRequired, true); assert.equal(receipt.consoleClientId, 'web-app');
  assert.equal((await pool.query('SELECT identity_organization_profile_data(profile) AS data FROM identity_organization_profiles profile WHERE tenant_id=$1', [receipt.tenantId])).rows[0].data.name, value.profile.name);
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_role_assignments WHERE user_id=$1', [receipt.administratorId])).rows[0].count, 0);
  assert.deepEqual(await status(value), { ...receipt, replayed: true }); assert.deepEqual(await activate(value), { ...receipt, replayed: true }); assert.deepEqual(await submit(value), { ...receipt, replayed: true });
  const authority = new AuthorizationState(database); const state = await authority.state(issuer, value.subject); assert.equal(state.active, true); assert.deepEqual(state.authentication, { required: true, maxAgeSeconds: 300 }); assert.deepEqual(state.roles, []);
  assert.equal((await authority.companyConsole(issuer, 'web-app', receipt.administratorId)).active, true); assert.equal((await authority.companyConsole(issuer, 'another-app', receipt.administratorId)).active, false);
  const authTime = Math.floor(Date.now() / 1000); const owner = { iss: issuer, sub: value.subject, actor_type: 'user', roles: state.roles, identity_authorization: state.context, jti: randomUUID(), exp: authTime + 300,
    auth_time: authTime, amr: ['pwd', 'otp'], mfa_authorization: { schemaVersion: 1, userId: receipt.administratorId, revision: '1', authTime, methods: ['pwd', 'otp'] } };
  const profiles = new (require('../OrganizationProfile').OrganizationProfile)(database, { revalidate: async () => {} }); const originalProfile = await profiles.get(owner);
  const updatedProfile = await profiles.save({ profile: { ...value.profile, city: 'Bern' }, reason: 'Actual own company owner profile update' }, originalProfile.etag, owner, 'Bearer real-native-owner'); assert.equal(updatedProfile.organization.city, 'Bern');
  assert.equal((await status(value)).status, 'active'); await enableTenant(database, schema, receipt.tenantId, false); assert.equal((await status(value)).status, 'suspended'); assert.equal((await authority.companyConsole(issuer, 'web-app', receipt.administratorId)).active, false);
});
test('unreviewed, rejected and foreign subjects cannot activate a candidate or change the configured console on replay', async () => {
  const pending = input(); await submit(pending); await assert.rejects(activate(pending), error => error.status === 400);
  const user = await reviewer(); const reviews = reviewStore(); const before = await reviews.get(pending.registrationId, user); await reviews.decide(pending.registrationId, { ...reviewBody, decision: 'rejected' }, before.etag, user, 'Bearer original'); await assert.rejects(activate(pending), error => error.status === 400);
  const value = await approvedRegistration(); await assert.rejects(activate({ ...value, subject: 'foreign-subject' }), error => error.status === 404); await activate(value);
  const body = { registrationId: value.registrationId, subject: value.subject, consoleClientId: 'another-app' }; await assert.rejects(store.receive('activate', body, proof(body, 'activate')), error => error.status === 409);
});
test('omitted activation or canonical outbox and cleared-scope unrelated writes roll the complete company activation back', async () => {
  const value = await approvedRegistration();
  for (const table of ['identity_company_activation_outbox', 'identity_organization_outbox', 'identity_user_outbox']) {
    await pool.query('CREATE FUNCTION activation_test_omit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL;END $$;CREATE TRIGGER zz_omit BEFORE INSERT ON ' + table + ' FOR EACH ROW EXECUTE FUNCTION activation_test_omit()');
    try { await assert.rejects(activate(value), error => error.status === 503); } finally { await pool.query('DROP TRIGGER zz_omit ON ' + table + ';DROP FUNCTION activation_test_omit()'); }
    assert.equal((await status(value)).status, 'pending-activation');
  }
  beforeCommit = async client => { await client.query("SELECT set_config('opendirectory.company_activation','',true)"); await client.query("INSERT INTO groups(id,name) VALUES(gen_random_uuid(),'Unrelated activation group')"); };
  await assert.rejects(activate(value), error => error.status === 503); beforeCommit = null; assert.equal((await status(value)).status, 'pending-activation');
});
test('original activation proof expiry rolls enabled resources and initial profile back at physical commit', async () => {
  const value = await approvedRegistration(); const body = { registrationId: value.registrationId, subject: value.subject, consoleClientId: 'web-app' }; const claims = proof(body, 'activate'); claims.exp = claims.iat + 2;
  beforeCommit = async () => { await new Promise(resolve => setTimeout(resolve, Math.max(0, claims.exp * 1000 - Date.now()) + 100)); };
  await assert.rejects(store.receive('activate', body, claims), error => error.status === 401); beforeCommit = null; assert.equal((await status(value)).status, 'pending-activation');
});
test('parallel own activations wait on the actual admission lock and commit one durable owner only', { timeout: 15000 }, async () => {
  const value = await approvedRegistration(); let readySignal; let release; const ready = new Promise(resolve => { readySignal = resolve; }); const gate = new Promise(resolve => { release = resolve; }); let hold = true;
  beforeCommit = async () => { if (hold) { hold = false; readySignal(); await gate; } }; const first = activate(value); await ready; const second = activate(value);
  try { let waiting = false; const until = Date.now() + 2500;
    while (Date.now() < until) { waiting = (await pool.query("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'SELECT identity_company_activate%') AS waiting")).rows[0].waiting; if (waiting) break; await new Promise(resolve => setTimeout(resolve, 10)); } assert.equal(waiting, true);
  } finally { release(); }
  const results = await Promise.all([first, second]); beforeCommit = null; assert.equal(results.filter(row => row.replayed).length, 1); assert.equal(results[0].administratorId, results[1].administratorId); assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_company_activations')).rows[0].count, 1);
});
test('activation migration replay preserves owner evidence and missing receiving or retained outbox fails closed', async () => {
  const value = await approvedRegistration(); const first = await activate(value); await pool.query(fs.readFileSync(path.join(migrations, '041_company_activations.sql'), 'utf8')); assert.deepEqual(await status(value), { ...first, replayed: true });
  await pool.query('ALTER TABLE identity_company_activations DISABLE TRIGGER identity_company_activation_commit');
  try { await assert.rejects(status(value), error => error.status === 503); } finally { await pool.query('ALTER TABLE identity_company_activations ENABLE TRIGGER identity_company_activation_commit'); }
  for (const sql of ["UPDATE identity_company_activations SET console_client_id='another-app'", 'DELETE FROM identity_company_activation_events']) await assert.rejects(pool.query(sql), error => error.code === '42501');
  await pool.query('ALTER TABLE identity_company_registrations DISABLE TRIGGER identity_company_registration_guard');
  try { await pool.query("UPDATE identity_company_registrations SET profile=jsonb_set(profile,'{city}','\"Forged city\"'::jsonb) WHERE id=$1", [value.registrationId]); }
  finally { await pool.query('ALTER TABLE identity_company_registrations ENABLE TRIGGER identity_company_registration_guard'); }
  await assert.rejects(status(value), error => error.status === 503);
  await pool.query('ALTER TABLE identity_company_registrations DISABLE TRIGGER identity_company_registration_guard');
  try { await pool.query('UPDATE identity_company_registrations SET profile=$1::jsonb WHERE id=$2', [JSON.stringify(value.profile), value.registrationId]); }
  finally { await pool.query('ALTER TABLE identity_company_registrations ENABLE TRIGGER identity_company_registration_guard'); }
  assert.equal((await status(value)).status, 'active');
  await pool.query('ALTER TABLE identity_company_activation_outbox DISABLE TRIGGER identity_company_activation_guard');
  try { await pool.query('DELETE FROM identity_company_activation_outbox'); } finally { await pool.query('ALTER TABLE identity_company_activation_outbox ENABLE TRIGGER identity_company_activation_guard'); }
  await assert.rejects(status(value), error => error.status === 503);
});
test('a limited SQL login and SET ROLE cannot launder the original activation proof through a granted definer', async () => {
  const value = await approvedRegistration(); const body = { registrationId: value.registrationId, subject: value.subject, consoleClientId: 'web-app' }; const claims = proof(body, 'activate'); const descriptor = { issuer, subject: value.subject, nonce: claims.jti, issuedAt: claims.iat, expiresAt: claims.exp, requestSha256: claims.body_sha256 };
  const role = 'activation_limited_' + randomUUID().replaceAll('-', ''); let limited; await administration.query('CREATE ROLE ' + role + ' LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS');
  try {
    await pool.query('GRANT USAGE ON SCHEMA ' + schema + ' TO ' + role + ';GRANT EXECUTE ON FUNCTION identity_company_activate(jsonb,jsonb) TO ' + role);
    const address = new URL(process.env.IDENTITY_TEST_DATABASE_URL); address.username = role; limited = new Pool({ connectionString: address.toString(), options: `-c search_path=${schema},public`, max: 1 });
    for (const assumed of [false, true]) { const client = await (assumed ? pool : limited).connect();
      try { await client.query('BEGIN'); if (assumed) await client.query('SET LOCAL ROLE ' + role); await assert.rejects(client.query('SELECT identity_company_activate($1::jsonb,$2::jsonb)', [JSON.stringify(descriptor), JSON.stringify(body)]), error => error.code === '42501' && error.message.includes('Actual database owner required')); }
      finally { await client.query('ROLLBACK'); client.release(); }
    }
  } finally { await limited?.end(); await pool.query('DROP OWNED BY ' + role); await administration.query('DROP ROLE ' + role); }
  assert.equal((await status(value)).status, 'pending-activation');
});
test('unlinking the original owner suspends effective applicant and console access even when the physical enabled flags stay true', async () => {
  const value = await approvedRegistration(); const receipt = await activate(value); await pool.query('DELETE FROM identity_subject_links WHERE issuer=$1 AND subject=$2', [issuer, value.subject]);
  const physical = (await pool.query('SELECT account.enabled AS user_enabled,tenant.enabled AS tenant_enabled FROM users account JOIN identity_tenants tenant ON tenant.id=$2 WHERE account.id=$1', [receipt.administratorId, receipt.tenantId])).rows[0]; assert.deepEqual(physical, { user_enabled: true, tenant_enabled: true });
  const current = await status(value); assert.equal(current.status, 'suspended'); assert.equal(current.tenantEnabled, true); assert.equal(current.administratorEnabled, false);
  assert.equal((await new AuthorizationState(database).companyConsole(issuer, 'web-app', receipt.administratorId)).active, false);
});
