'use strict';

const { test, before, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { Pool } = require('pg');
const { CompanyOffboarding } = require('../CompanyOffboarding');
const { DeviceOffboardingAuthority } = require('../DeviceOffboardingAuthority');
const { CompanyRegistrations } = require('../CompanyRegistrations');
const { CompanyRegistrationReviews } = require('../CompanyRegistrationReviews');
const { CompanyLicenseAuthority } = require('../CompanyLicenseAuthority');
const { CompanyBlueprintAuthority } = require('../CompanyBlueprintAuthority');
const { CompanyBlueprintAssignmentAuthority } = require('../CompanyBlueprintAssignmentAuthority');
const { COMPANY_BLUEPRINT_ASSIGNMENT_PERMISSIONS, validSource: validBlueprintAssignmentSource } = require('../../../../../packages/company-blueprint-assignment-contract');
const { COMPANY_BLUEPRINT_PERMISSIONS, validSource: validBlueprintSource } = require('../../../../../packages/company-blueprint-contract');
const { AuthorizationState } = require('../AuthorizationState');
const { DirectoryCreator } = require('../DirectoryCreator');
const { DirectoryUsers, userEtag } = require('../DirectoryUsers');
const { UserMutator } = require('../UserMutator');
const { sameContext } = require('../../../../../packages/identity-authorization-contract');
const { provisionTenant, adoptTenant, enableTenant } = require('../../../../../scripts/lib/tenant-ownership-fixture.cjs');
const { changeOperator } = require('../../scripts/company-review-operator');
const { PURPOSE, AUDIENCE, BASE_PATH } = require('../../../../../packages/company-registration-contract');
const { requestDigest } = require('../../../../../packages/company-registration-contract/digest');
const schema = 'company_offboarding_' + randomUUID().replaceAll('-', '');
const issuer = 'https://company-offboarding.test';
const administration = new Pool({ connectionString: process.env.IDENTITY_TEST_DATABASE_URL, max: 1 });
let database; let pool;
before(async () => {
  await administration.query('CREATE SCHEMA ' + schema);
  const address = new URL(process.env.IDENTITY_TEST_DATABASE_URL); address.searchParams.set('options', '-c search_path=' + schema + ',public');
  process.env.DATABASE_URL = address.toString(); database = require('../db'); pool = database.pool;
  assert.equal(await database.initDb(), true);
});
beforeEach(async () => {
  for (const table of ['identity_company_offboarding_receipts', 'identity_company_offboarding_outbox']) await pool.query('ALTER TABLE ' + table + ' DISABLE TRIGGER identity_company_offboarding_no_truncate');
  try { await pool.query('TRUNCATE identity_tenants,users,groups,ous,identity_deleted_users,identity_directory_user_events,identity_company_offboarding_receipts,identity_company_offboarding_outbox CASCADE'); }
  finally { for (const table of ['identity_company_offboarding_receipts', 'identity_company_offboarding_outbox']) await pool.query('ALTER TABLE ' + table + ' ENABLE TRIGGER identity_company_offboarding_no_truncate'); }
});
after(async () => { await pool?.end(); await administration.query('DROP SCHEMA ' + schema + ' CASCADE'); await administration.end(); });
async function token(userId, subject) {
  const state = await new AuthorizationState(database).state(issuer, subject); const now = Math.floor(Date.now() / 1000);
  return { iss: issuer, sub: subject, actor_type: 'user', roles: state.roles, identity_authorization: state.context, jti: randomUUID(), exp: now + 600,
    auth_time: now, amr: ['pwd', 'otp'], mfa_authorization: { schemaVersion: 1, userId, revision: '1', authTime: now, methods: ['pwd', 'otp'] } };
}
async function admin(tenant, role = 'admin') {
  tenant ||= await provisionTenant(database, schema, { enabled: true }); const id = randomUUID(); const subject = 'operator-' + id;
  await pool.query('INSERT INTO users(id,username,email) VALUES($1,$2,$3)', [id, subject, subject + '@test.invalid']);
  await pool.query('INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES($1,$2,$3)', [issuer, subject, id]);
  await adoptTenant(database, schema, tenant, [{ kind: 'user', resourceId: id }]);
  if (role) await pool.query('INSERT INTO identity_role_assignments(user_id,role,reason) VALUES($1,$2,$3)', [id, role, 'Explicit original offboarding test operator']);
  return { user: await token(id, subject), tenant };
}
function settings(live = {}) {
  return { issuer, revalidate: async (authorization, user) => {
    assert.match(authorization, /^Bearer original/); if (live.check) await live.check();
    const state = await new AuthorizationState(database).state(issuer, user.sub);
    if (live.withdrawn || !state.active || !sameContext(state.context, user.identity_authorization)) throw Object.assign(new Error('Original source withdrawn'), { status: 401 });
    return state.tenant;
  } };
}
async function owner() {
  const reviewer = await admin(undefined, null); const reviewerId = reviewer.user.identity_authorization.userId;
  await changeOperator(database, { issuer, userId: reviewerId, version: '0', enabled: true, reason: 'Explicit independent company review fixture' });
  reviewer.user = await token(reviewerId, reviewer.user.sub);
  const subject = 'owner-' + randomUUID(); const value = { registrationId: randomUUID(), subject,
    principal: { username: subject, email: subject + '@test.invalid', displayName: 'Original owner' },
    profile: { name: 'Offboarding Test AG', legalForm: 'AG', registrationNumber: '', taxId: '', addressLine1: 'Test Street 1', addressLine2: '',
      postalCode: '8000', city: 'Zürich', country: 'CH', timezone: 'UTC', defaultLanguage: 'de', contactEmail: 'office@test.invalid', contactPhone: '', website: '' } };
  const store = new CompanyRegistrations(database);
  const receive = (operation, body) => { const now = Math.floor(Date.now() / 1000); return store.receive(operation, body, { iss: issuer, sub: 'oauth-provider', aud: AUDIENCE,
    token_use: PURPOSE, actor_type: 'workload', htm: 'POST', htu: BASE_PATH + '/' + operation, body_sha256: requestDigest(operation, body), registration_subject: subject,
    jti: randomUUID(), iat: now, exp: now + 30 }); };
  await receive('submit', value); const reviews = new CompanyRegistrationReviews(database, { revalidate: (user, authorization) => settings().revalidate(authorization, user) });
  const pending = await reviews.get(value.registrationId, reviewer.user);
  await reviews.decide(value.registrationId, { decision: 'approved', reason: 'Independently reviewed actual company', confirm: true }, pending.etag, reviewer.user, 'Bearer original');
  const activated = await receive('activate', { registrationId: value.registrationId, subject, consoleClientId: 'web-app' });
  return { user: await token(activated.administratorId, subject), tenant: activated.tenantId };
}
const load = id => new DirectoryUsers(database).get(id);
async function employee(actor, enabled = true) {
  const person = await new DirectoryCreator(database, settings()).user({ username: 'employee-' + randomUUID(), email: randomUUID() + '@test.invalid' }, actor.user, 'Bearer original');
  return enabled ? new UserMutator(database, settings()).update(person.id, { enabled: true }, userEtag(person), actor.user, 'Bearer original') : person;
}
const command = person => ({ workflowId: randomUUID(), expectedRevision: person.revision, confirm: true });
const receive = (actor, person, body, db = database, options = settings()) => new CompanyOffboarding(db, options).receive(person.id, body, actor.user, 'Bearer original');
const evidence = async () => (await pool.query(`SELECT receipt.*,outbox.status FROM identity_company_offboarding_receipts receipt
  JOIN identity_company_offboarding_outbox outbox USING(tenant_id,workflow_id)`)).rows;
function wrapped(hook) { return { ...database, transaction: (operation, options = {}) => database.transaction(async client => {
  const result = await operation(client); if (!options.readOnly) await hook(client, result); return result;
}, options) }; }

test('separate Blueprint assignment source uses actual roleless Owner activation without writing roles, profiles, audit or application authority', async () => {
  const actor = await owner(); actor.user.token_use = 'access'; assert.deepEqual(actor.user.roles, []);
  const tables = ['users', 'identity_role_assignments', 'identity_company_registrations', 'identity_company_registration_reviews', 'identity_company_activations',
    'identity_company_activation_events', 'identity_company_activation_outbox', 'identity_authorization_audit', 'identity_user_record_audit', 'identity_user_audit', 'identity_user_outbox'];
  const snapshot = async () => Object.fromEntries(await Promise.all(tables.map(async table => [table, (await pool.query('SELECT to_jsonb(source) AS value FROM ' + table + ' source ORDER BY to_jsonb(source)::text')).rows])));
  const before = await snapshot(); let transactions = 0;
  const observed = { ...database, transaction: (operation, options) => database.transaction(async client => {
    transactions++; assert.deepEqual(options, { readOnly: true });
    assert.deepEqual((await client.query("SELECT current_setting('transaction_read_only') AS read_only,current_setting('transaction_isolation') AS isolation")).rows[0], { read_only: 'on', isolation: 'repeatable read' });
    return operation(client);
  }, options) };
  const source = await new CompanyBlueprintAssignmentAuthority(observed, settings()).read(actor.user, 'Bearer original');
  assert.deepEqual(Object.keys(source), ['schemaVersion', 'companyBlueprintAssignmentsProtocol', 'issuer', 'subject', 'tokenId', 'expiresAt', 'context', 'tenant', 'actorUserId', 'permissions', 'validUntil', 'target']);
  assert.deepEqual(source.permissions, COMPANY_BLUEPRINT_ASSIGNMENT_PERMISSIONS); assert.equal(source.target, null); assert.equal(source.tenant.id, actor.tenant);
  assert.equal(source.actorUserId, actor.user.identity_authorization.userId); assert.equal(source.validUntil, actor.user.auth_time + 300); assert.equal(validBlueprintAssignmentSource(source, actor.user), true);
  assert.equal(transactions, 1); assert.deepEqual(await snapshot(), before); assert.deepEqual((await new AuthorizationState(database).state(issuer, actor.user.sub)).roles, []);
  const blueprint = await new CompanyBlueprintAuthority(database, settings()).read(actor.user, 'Bearer original');
  const application = await new CompanyLicenseAuthority(database, settings()).read(actor.user, 'Bearer original');
  assert.equal(Object.keys(blueprint).length, 11); assert.deepEqual(blueprint.permissions, COMPANY_BLUEPRINT_PERMISSIONS);
  assert.equal(Object.keys(application).length, 11); assert.deepEqual(application.permissions, ['company.apps.read', 'company.apps.create', 'company.apps.assign']);
});
test('Blueprint assignment source exposes exact own-user positive, disabled and deleted generations with no profile projection', async () => {
  const actor = await owner(); actor.user.token_use = 'access'; const person = await employee(actor); const source = new CompanyBlueprintAssignmentAuthority(database, settings());
  const read = () => source.read(actor.user, 'Bearer original', { userId: person.id });
  const positiveAccount = (await pool.query('SELECT authorization_revision,eligibility_revision FROM users WHERE id=$1', [person.id])).rows[0];
  const positive = await read(); assert.deepEqual(positive.target, { id: person.id, revision: String(positiveAccount.authorization_revision), eligibilityRevision: String(positiveAccount.eligibility_revision), enabled: true, deleted: false });
  assert.equal(validBlueprintAssignmentSource(positive, actor.user, person.id), true);
  const disabled = await new UserMutator(database, settings()).update(person.id, { enabled: false }, userEtag(person), actor.user, 'Bearer original');
  const negativeAccount = (await pool.query('SELECT authorization_revision,eligibility_revision FROM users WHERE id=$1', [person.id])).rows[0];
  const negative = await read(); assert.deepEqual(negative.target, { id: person.id, revision: String(negativeAccount.authorization_revision), eligibilityRevision: String(negativeAccount.eligibility_revision), enabled: false, deleted: false });
  assert.equal(validBlueprintAssignmentSource(negative, actor.user, person.id), true);
  const administrator = await admin(actor.tenant); await new UserMutator(database, settings()).remove(person.id, userEtag(disabled), administrator.user, 'Bearer original');
  const deleted = (await pool.query('SELECT revision FROM identity_deleted_users WHERE user_id=$1', [person.id])).rows[0];
  const tombstone = await read(); assert.deepEqual(tombstone.target, { id: person.id, revision: null, eligibilityRevision: String(deleted.revision), enabled: false, deleted: true });
  assert.equal(validBlueprintAssignmentSource(tombstone, actor.user, person.id), true); assert.equal((await pool.query('SELECT id FROM users WHERE id=$1', [person.id])).rows.length, 0);
});
test('Blueprint assignment source retains actual Owner and home administration while denying foreign or missing targets and token-selected homes', async () => {
  const first = await owner(); const second = await owner(); const person = await employee(first); const foreign = await employee(second); const administrator = await admin(first.tenant);
  for (const actor of [first, second, administrator]) actor.user.token_use = 'access';
  const source = new CompanyBlueprintAssignmentAuthority(database, settings());
  for (const actor of [first, administrator]) {
    const claimed = { ...actor.user, roles: [], permissions: [], tenant: { id: second.tenant } };
    const value = await source.read(claimed, 'Bearer original', { userId: person.id }); assert.equal(value.tenant.id, first.tenant); assert.equal(value.target.id, person.id);
    for (const userId of [foreign.id, randomUUID()]) await assert.rejects(source.read(claimed, 'Bearer original', { userId }), error => error.status === 404);
  }
  assert.equal((await source.read(second.user, 'Bearer original', { userId: foreign.id })).tenant.id, second.tenant);
});
test('actual global Policy and license duties do not grant the separate Blueprint assignment source', async () => {
  const actor = await owner(); const source = new CompanyBlueprintAssignmentAuthority(database, settings());
  for (const role of [null, 'policy-administrator', 'license-administrator']) {
    const ordinary = await admin(actor.tenant, role); ordinary.user.token_use = 'access';
    await assert.rejects(source.read({ ...ordinary.user, roles: ['admin'], permissions: [...COMPANY_BLUEPRINT_ASSIGNMENT_PERMISSIONS, 'company.apps.assign'] }, 'Bearer original'), error => error.status === 403);
  }
});
test('actual Blueprint assignment readers require fresh independently bound MFA and the original human bearer', async () => {
  const actualOwner = await owner(); const actualAdmin = await admin(actualOwner.tenant); const source = new CompanyBlueprintAssignmentAuthority(database, settings());
  for (const actor of [actualOwner, actualAdmin]) {
    actor.user.token_use = 'access'; const stale = structuredClone(actor.user); stale.auth_time -= 301; stale.mfa_authorization.authTime -= 301;
    const unbound = structuredClone(actor.user); unbound.mfa_authorization.userId = randomUUID();
    for (const user of [stale, unbound, { ...actor.user, mfa_authorization: undefined }]) await assert.rejects(source.read(user, 'Bearer original'), error => error.status === 428);
    await assert.rejects(source.read({ ...actor.user, actor_type: 'application' }, 'Bearer original'), error => error.status === 403);
    await assert.rejects(source.read(actor.user, 'Basic original'), error => error.status === 401);
  }
});
test('Blueprint assignment source cannot refresh withdrawn original account, subject or tenant authority', async () => {
  const actor = await owner(); actor.user.token_use = 'access'; const live = {}; const source = new CompanyBlueprintAssignmentAuthority(database, settings(live));
  await source.read(actor.user, 'Bearer original'); live.withdrawn = true;
  await assert.rejects(source.read(actor.user, 'Bearer original'), error => error.status === 401); live.withdrawn = false;
  await pool.query('UPDATE users SET enabled=false WHERE id=$1', [actor.user.identity_authorization.userId]);
  await assert.rejects(source.read(actor.user, 'Bearer original'), error => error.status === 401);
  await pool.query('UPDATE users SET enabled=true WHERE id=$1', [actor.user.identity_authorization.userId]); actor.user = { ...await token(actor.user.identity_authorization.userId, actor.user.sub), token_use: 'access' };
  await enableTenant(database, schema, actor.tenant, false); await assert.rejects(source.read(actor.user, 'Bearer original'), error => error.status === 401);
  await enableTenant(database, schema, actor.tenant, true); actor.user = { ...await token(actor.user.identity_authorization.userId, actor.user.sub), token_use: 'access' };
  await source.read(actor.user, 'Bearer original'); await pool.query('DELETE FROM identity_subject_links WHERE issuer=$1 AND subject=$2', [issuer, actor.user.sub]);
  await assert.rejects(source.read(actor.user, 'Bearer original'), error => error.status === 401);
});
test('final original tenant suspension discards the Blueprint assignment target source', async () => {
  const actor = await owner(); actor.user.token_use = 'access'; const person = await employee(actor); let checks = 0;
  const live = { check: async () => { if (++checks === 2) await enableTenant(database, schema, actor.tenant, false); } };
  await assert.rejects(new CompanyBlueprintAssignmentAuthority(database, settings(live)).read(actor.user, 'Bearer original', { userId: person.id }), error => error.status === 401); assert.equal(checks, 2);
});
test('missing actual company activation receiving evidence cannot mint Blueprint assignment duties', async () => {
  const actor = await owner(); actor.user.token_use = 'access'; const source = new CompanyBlueprintAssignmentAuthority(database, settings());
  await pool.query('ALTER TABLE identity_company_activation_outbox DISABLE TRIGGER USER');
  try { await pool.query('DELETE FROM identity_company_activation_outbox WHERE tenant_id=$1', [actor.tenant]); }
  finally { await pool.query('ALTER TABLE identity_company_activation_outbox ENABLE TRIGGER USER'); }
  await assert.rejects(source.read(actor.user, 'Bearer original'), error => error.status === 503);
});

test('company Blueprint source uses actual independent registration approval and activation without adding roles or changing canonical records', async () => {
  const actor = await owner(); assert.deepEqual(actor.user.roles, []);
  const tables = ['users', 'identity_role_assignments', 'identity_company_registrations', 'identity_company_registration_reviews', 'identity_company_activations',
    'identity_company_activation_events', 'identity_company_activation_outbox', 'identity_authorization_audit', 'identity_user_record_audit', 'identity_user_audit', 'identity_user_outbox'];
  const snapshot = async () => Object.fromEntries(await Promise.all(tables.map(async table => [table, (await pool.query('SELECT to_jsonb(source) AS value FROM ' + table + ' source ORDER BY to_jsonb(source)::text')).rows])));
  const before = await snapshot(); let sourceTransactions = 0;
  const observed = { ...database, transaction: (operation, options) => database.transaction(async client => {
    sourceTransactions++; assert.deepEqual(options, { readOnly: true });
    assert.deepEqual((await client.query("SELECT current_setting('transaction_read_only') AS read_only,current_setting('transaction_isolation') AS isolation")).rows[0], { read_only: 'on', isolation: 'repeatable read' });
    return operation(client);
  }, options) };
  const source = await new CompanyBlueprintAuthority(observed, settings()).read(actor.user, 'Bearer original');
  assert.deepEqual(Object.keys(source), ['schemaVersion', 'companyBlueprintProtocol', 'issuer', 'subject', 'tokenId', 'expiresAt', 'context', 'tenant', 'actorUserId', 'permissions', 'validUntil']);
  assert.equal(validBlueprintSource(source, { ...actor.user, token_use: 'access' }), true); assert.deepEqual(source.permissions, COMPANY_BLUEPRINT_PERMISSIONS);
  assert.equal(source.tenant.id, actor.tenant); assert.equal(source.actorUserId, actor.user.identity_authorization.userId); assert.equal(source.validUntil, actor.user.auth_time + 300);
  assert.equal(sourceTransactions, 1); assert.deepEqual(await snapshot(), before); assert.deepEqual((await new AuthorizationState(database).state(issuer, actor.user.sub)).roles, []);
});
test('separate company Blueprint sources keep actual Owner and canonical administrator homes despite claimed token tenant or global permissions', async () => {
  const first = await owner(); const second = await owner(); const administrator = await admin(first.tenant);
  const source = new CompanyBlueprintAuthority(database, settings());
  const claimed = { ...first.user, roles: ['admin', 'policy-administrator'], permissions: ['policies.publish'], tenant: { id: second.tenant } };
  assert.equal((await source.read(claimed, 'Bearer original')).tenant.id, first.tenant);
  assert.equal((await source.read(second.user, 'Bearer original')).tenant.id, second.tenant);
  const actualAdmin = await source.read({ ...administrator.user, roles: [], permissions: [], tenant: { id: second.tenant } }, 'Bearer original');
  assert.equal(actualAdmin.tenant.id, first.tenant); assert.deepEqual(actualAdmin.permissions, COMPANY_BLUEPRINT_PERMISSIONS);
  await assert.rejects(source.read({ ...first.user, identity_authorization: second.user.identity_authorization,
    mfa_authorization: { ...first.user.mfa_authorization, userId: second.user.identity_authorization.userId } }, 'Bearer original'), error => error.status === 401);
});
test('actual global Policy or license roles and claimed company rights cannot replace current Owner or canonical home administration', async () => {
  const actor = await owner(); const source = new CompanyBlueprintAuthority(database, settings());
  for (const role of [null, 'policy-administrator', 'license-administrator']) {
    const ordinary = await admin(actor.tenant, role);
    await assert.rejects(source.read({ ...ordinary.user, roles: ['admin'], permissions: [...COMPANY_BLUEPRINT_PERMISSIONS, 'policies.publish'] }, 'Bearer original'), error => error.status === 403);
  }
});
test('actual Owner and home administrator need independently bound fresh MFA even for a read-only Blueprint source', async () => {
  const actualOwner = await owner(); const actualAdmin = await admin(actualOwner.tenant); const source = new CompanyBlueprintAuthority(database, settings());
  for (const actor of [actualOwner, actualAdmin]) {
    const stale = structuredClone(actor.user); stale.auth_time -= 301; stale.mfa_authorization.authTime -= 301;
    const unbound = structuredClone(actor.user); unbound.mfa_authorization.userId = randomUUID();
    for (const user of [stale, unbound, { ...actor.user, mfa_authorization: undefined }]) await assert.rejects(source.read(user, 'Bearer original'), error => error.status === 428);
    await assert.rejects(source.read({ ...actor.user, actor_type: 'application' }, 'Bearer original'), error => error.status === 403);
  }
});
test('canonical Owner source fails closed when actual account, subject link, tenant generation or original authority changes', async () => {
  const actor = await owner(); const live = {}; const source = new CompanyBlueprintAuthority(database, settings(live));
  await source.read(actor.user, 'Bearer original');
  live.withdrawn = true; await assert.rejects(source.read(actor.user, 'Bearer original'), error => error.status === 401); live.withdrawn = false;
  await pool.query('UPDATE users SET enabled=false WHERE id=$1', [actor.user.identity_authorization.userId]);
  await assert.rejects(source.read(actor.user, 'Bearer original'), error => error.status === 401);
  await pool.query('UPDATE users SET enabled=true WHERE id=$1', [actor.user.identity_authorization.userId]); actor.user = await token(actor.user.identity_authorization.userId, actor.user.sub);
  await enableTenant(database, schema, actor.tenant, false); await assert.rejects(source.read(actor.user, 'Bearer original'), error => error.status === 401);
  await enableTenant(database, schema, actor.tenant, true); actor.user = await token(actor.user.identity_authorization.userId, actor.user.sub);
  await source.read(actor.user, 'Bearer original');
  await pool.query('DELETE FROM identity_subject_links WHERE issuer=$1 AND subject=$2', [issuer, actor.user.sub]);
  await assert.rejects(source.read(actor.user, 'Bearer original'), error => error.status === 401);
});
test('final original Blueprint authority check discards a source when the actual tenant is suspended during the read', async () => {
  const actor = await owner(); let checks = 0; const live = { check: async () => { if (++checks === 2) await enableTenant(database, schema, actor.tenant, false); } };
  await assert.rejects(new CompanyBlueprintAuthority(database, settings(live)).read(actor.user, 'Bearer original'), error => error.status === 401); assert.equal(checks, 2);
});
test('missing retained company activation outbox cannot mint a Blueprint source for an otherwise current roleless Owner', async () => {
  const actor = await owner(); const source = new CompanyBlueprintAuthority(database, settings());
  await pool.query('ALTER TABLE identity_company_activation_outbox DISABLE TRIGGER USER');
  try { await pool.query('DELETE FROM identity_company_activation_outbox WHERE tenant_id=$1', [actor.tenant]); }
  finally { await pool.query('ALTER TABLE identity_company_activation_outbox ENABLE TRIGGER USER'); }
  await assert.rejects(source.read(actor.user, 'Bearer original'), error => error.status === 503);
});
test('missing current activation receiver is unavailable instead of a fallback Blueprint or global Policy grant', async () => {
  const actor = await owner(); const source = new CompanyBlueprintAuthority(database, settings());
  await pool.query('ALTER TABLE identity_company_activations DISABLE TRIGGER identity_company_activation_commit');
  try { await assert.rejects(source.read(actor.user, 'Bearer original'), error => error.status === 503); }
  finally { await pool.query('ALTER TABLE identity_company_activations ENABLE TRIGGER identity_company_activation_commit'); }
});

test('actual roleless Owner reads a thirteen-field device return source from the retained negative account checkpoint without a second identity write', async () => {
  const actor = await owner(); const person = await employee(actor); const body = command(person); const parent = await receive(actor, person, body);
  const read = () => new DeviceOffboardingAuthority(database, settings()).read(actor.user, 'Bearer original', { workflowId: body.workflowId, userId: person.id });
  const source = await read(); assert.deepEqual(actor.user.roles, []); assert.equal(Object.keys(source).length, 13); assert.equal(source.deviceOffboardingReturnsProtocol, 1);
  assert.deepEqual(source.permissions, ['devices.inventory.read', 'devices.inventory.create', 'devices.inventory.assign']);
  assert.deepEqual(source.target, { id: person.id, enabled: false, eligibilityRevision: parent.afterEligibilityRevision });
  assert.equal(source.parent.operationId, parent.operationId); assert.equal(source.parent.tenantId, actor.tenant); assert.equal(source.parent.deliveryStatus, 'pending');
  const before = (await pool.query('SELECT authorization_revision FROM users WHERE id=$1', [person.id])).rows[0].authorization_revision;
  await pool.query("INSERT INTO identity_role_assignments(user_id,role,reason) VALUES($1,'directory-reader','Canonical SQL role counter fixture after actual account disable')", [person.id]);
  assert.notEqual((await pool.query('SELECT authorization_revision FROM users WHERE id=$1', [person.id])).rows[0].authorization_revision, before);
  const retained = await evidence(); assert.deepEqual(await read(), source); assert.deepEqual(await evidence(), retained);
});
test('device return source cannot reuse a parent after reactivation and redisabling', async () => {
  const actor = await owner(); const person = await employee(actor); const body = command(person); await receive(actor, person, body);
  const source = new DeviceOffboardingAuthority(database, settings()); const selectors = { workflowId: body.workflowId, userId: person.id };
  const inactive = await load(person.id); const enabled = await new UserMutator(database, settings()).update(person.id, { enabled: true }, userEtag(inactive), actor.user, 'Bearer original');
  await assert.rejects(source.read(actor.user, 'Bearer original', selectors), error => error.status === 409);
  await new UserMutator(database, settings()).update(person.id, { enabled: false }, userEtag(enabled), actor.user, 'Bearer original');
  await assert.rejects(source.read(actor.user, 'Bearer original', selectors), error => error.status === 409); assert.equal((await evidence()).length, 1);
});
test('device return source denies foreign home, self, missing parent and claimed inventory roles', async () => {
  const actor = await owner(); const person = await employee(actor); const body = command(person); await receive(actor, person, body);
  const source = new DeviceOffboardingAuthority(database, settings()); const selectors = { workflowId: body.workflowId, userId: person.id };
  await assert.rejects(source.read((await admin()).user, 'Bearer original', selectors), error => error.status === 404);
  await assert.rejects(source.read(actor.user, 'Bearer original', { ...selectors, userId: actor.user.identity_authorization.userId }), error => error.status === 403);
  await assert.rejects(source.read(actor.user, 'Bearer original', { ...selectors, workflowId: randomUUID() }), error => error.status === 409);
  const ordinary = await admin(actor.tenant, null); await assert.rejects(source.read({ ...ordinary.user, roles: ['admin'], permissions: ['devices.inventory.assign'] }, 'Bearer original', selectors), error => error.status === 403);
});
test('device return source requires fresh independent MFA even for an actual own administrative reader', async () => {
  const actor = await admin(); const person = await employee(actor); const body = command(person); await receive(actor, person, body);
  const stale = structuredClone(actor.user); stale.auth_time -= 301; stale.mfa_authorization.authTime -= 301;
  await assert.rejects(new DeviceOffboardingAuthority(database, settings()).read(stale, 'Bearer original', { workflowId: body.workflowId, userId: person.id }), error => error.status === 428);
});
test('device return source cannot acknowledge a parent whose actual mandatory outbox was removed', async () => {
  const actor = await owner(); const person = await employee(actor); const body = command(person); await receive(actor, person, body);
  await pool.query('ALTER TABLE identity_company_offboarding_outbox DISABLE TRIGGER USER');
  try { await pool.query('DELETE FROM identity_company_offboarding_outbox WHERE tenant_id=$1 AND workflow_id=$2', [actor.tenant, body.workflowId]); }
  finally { await pool.query('ALTER TABLE identity_company_offboarding_outbox ENABLE TRIGGER USER'); }
  await assert.rejects(new DeviceOffboardingAuthority(database, settings()).read(actor.user, 'Bearer original', { workflowId: body.workflowId, userId: person.id }), error => error.status === 503);
});

test('actual roleless Owner disables atomically with original UserMutator audit, eligibility evidence and pending receipt/outboxes', async () => {
  const actor = await owner(); assert.deepEqual(actor.user.roles, []);
  await pool.query("SELECT setval('identity_user_record_revision_seq',9007199254740993)");
  const person = await employee(actor); const body = command(person);
  const before = (await pool.query('SELECT eligibility_revision FROM users WHERE id=$1', [person.id])).rows[0];
  await pool.query("SELECT setval('identity_user_revision_seq',9007199254740993)");
  const result = await receive(actor, person, body);
  assert.deepEqual(Object.keys(result), ['schemaVersion', 'workflowId', 'tenantId', 'userId', 'actorUserId', 'operationId', 'action', 'beforeRevision', 'afterRevision', 'beforeEligibilityRevision', 'afterEligibilityRevision', 'createdAt', 'deliveryStatus']);
  assert.equal(result.action, 'disabled'); assert.equal(result.beforeRevision, person.revision); assert.equal(result.beforeEligibilityRevision, String(before.eligibility_revision));
  assert.ok(BigInt(result.beforeRevision) > 9007199254740991n); assert.ok(BigInt(result.afterRevision) > BigInt(result.beforeRevision));
  assert.ok(BigInt(result.afterEligibilityRevision) > 9007199254740991n); assert.notEqual(BigInt(result.afterEligibilityRevision), BigInt(result.beforeEligibilityRevision) + 1n);
  assert.equal((await load(person.id)).enabled, false); const rows = await evidence(); assert.equal(rows.length, 1); assert.equal(rows[0].status, 'pending');
  const event = (await pool.query('SELECT * FROM identity_directory_user_events WHERE id=$1', [result.operationId])).rows[0];
  assert.equal(event.actor.userId, result.actorUserId); assert.equal(event.details.beforeRevision, result.beforeRevision); assert.equal(event.details.afterRevision, result.afterRevision);
  for (const table of ['identity_directory_user_outbox', 'identity_user_outbox']) assert.ok((await pool.query('SELECT count(*)::int AS count FROM ' + table)).rows[0].count > 0);
  const serialized = JSON.stringify(rows); for (const secret of ['Bearer', actor.user.jti, person.email, person.username]) assert.equal(serialized.includes(secret), false);
});
test('lost response and refreshed original bearer return identical receipt, with metadata changes tolerated in the same eligibility generation', async () => {
  const actor = await admin(); const person = await employee(actor); const body = command(person); const first = await receive(actor, person, body);
  actor.user = await token(actor.user.identity_authorization.userId, actor.user.sub);
  const disabled = await load(person.id); await new UserMutator(database, settings()).update(person.id, { title: 'Metadata after receipt' }, userEtag(disabled), actor.user, 'Bearer original');
  const count = (await pool.query('SELECT count(*)::int AS count FROM identity_directory_user_events')).rows[0].count;
  assert.deepEqual(await receive(actor, person, body), first); assert.equal((await evidence()).length, 1);
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_directory_user_events')).rows[0].count, count);
});
test('another current actual home administrator recovers the original actor receipt without impersonation claims', async () => {
  const actor = await owner(); const person = await employee(actor); const body = command(person); const first = await receive(actor, person, body);
  const current = await admin(actor.tenant); assert.notEqual(current.user.identity_authorization.userId, first.actorUserId);
  await pool.query('DELETE FROM identity_subject_links WHERE issuer=$1 AND subject=$2', [issuer, actor.user.sub]);
  assert.deepEqual(await receive(current, person, body), first);
});
test('already disabled validates record revision and stores only an observation without any user update effects', async () => {
  const actor = await admin(); const person = await employee(actor, false); const body = command(person);
  const before = await load(person.id); const count = (await pool.query('SELECT count(*)::int AS count FROM identity_directory_user_events')).rows[0].count;
  const first = await receive(actor, person, body); assert.equal(first.action, 'already_disabled'); assert.equal(first.operationId, null);
  assert.equal(first.beforeRevision, first.afterRevision); assert.equal(first.beforeEligibilityRevision, first.afterEligibilityRevision); assert.deepEqual(await load(person.id), before);
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_directory_user_events')).rows[0].count, count); assert.deepEqual(await receive(actor, person, body), first);
});
test('stale expected record revision returns 412 for enabled and already disabled accounts without receipts', async () => {
  const actor = await admin();
  for (const enabled of [true, false]) { const person = await employee(actor, enabled); const body = { ...command(person), expectedRevision: '9223372036854775807' };
    await assert.rejects(receive(actor, person, body), error => error.status === 412); assert.deepEqual(await load(person.id), person); }
  assert.equal((await evidence()).length, 0);
});
test('same workflow cannot substitute another own target or expected revision', async () => {
  const actor = await admin(); const person = await employee(actor); const other = await employee(actor); const body = command(person); await receive(actor, person, body);
  await assert.rejects(receive(actor, person, { ...body, expectedRevision: '1' }), error => error.status === 409);
  await assert.rejects(receive(actor, other, body), error => error.status === 409); assert.equal((await load(other.id)).enabled, true); assert.equal((await evidence()).length, 1);
});
test('reenabling and disabling again invalidates recovery of the older workflow, even though the account is disabled', async () => {
  const actor = await admin(); const person = await employee(actor); const body = command(person); const first = await receive(actor, person, body);
  const mutator = new UserMutator(database, settings()); const disabled = await load(person.id);
  const enabled = await mutator.update(person.id, { enabled: true }, userEtag(disabled), actor.user, 'Bearer original');
  await assert.rejects(receive(actor, person, body), error => error.code === '23514');
  await mutator.update(person.id, { enabled: false }, userEtag(enabled), actor.user, 'Bearer original');
  await assert.rejects(receive(actor, person, body), error => error.code === '23514'); assert.equal((await evidence())[0].after_eligibility_revision, first.afterEligibilityRevision);
});
test('canonical self, foreign targets and foreign workflow keys cannot read receipt storage or lock foreign accounts', async () => {
  const actor = await admin(); const foreignActor = await admin(); const foreign = await employee(foreignActor); const body = command(foreign); await receive(foreignActor, foreign, body);
  const blocker = await pool.connect(); await blocker.query('BEGIN'); await blocker.query('SELECT id FROM users WHERE id=$1 FOR UPDATE', [foreign.id]);
  let queriedReceipt = false; const observed = { ...database, transaction: (operation, options) => database.transaction(client => operation({ query: async (sql, values) => {
    if (sql.includes('FROM identity_company_offboarding_receipts')) queriedReceipt = true; return client.query(sql, values);
  } }), options) };
  try {
    await assert.rejects(receive(actor, { id: actor.user.identity_authorization.userId.toUpperCase() }, body, observed), error => error.status === 403);
    await assert.rejects(receive(actor, foreign, body, observed), error => error.status === 404); assert.equal(queriedReceipt, false);
  } finally { await blocker.query('ROLLBACK'); blocker.release(); }
  const own = await employee(actor); assert.equal((await receive(actor, own, { ...command(own), workflowId: body.workflowId })).tenantId, actor.tenant);
});
test('claimed admin, directory operator, workload and missing or stale MFA cannot pass the actual company source', async () => {
  const actor = await admin(undefined, 'user-administrator'); const person = await employee(actor);
  for (const user of [actor.user, { ...actor.user, roles: ['admin'] }, { ...actor.user, actor_type: 'application' }])
    await assert.rejects(receive({ ...actor, user }, person, command(person)), error => error.status === 403);
  const actual = await admin(actor.tenant);
  for (const user of [{ ...actual.user, mfa_authorization: undefined }, { ...actual.user, auth_time: actual.user.auth_time - 301 }])
    await assert.rejects(receive({ ...actual, user }, person, command(person)), error => error.status === 428);
  for (const permissions of [['users.update'], ['users.status.manage'], []])
    await assert.rejects(receive({ ...actual, user: { ...actual.user, roles: [], permissions } }, person, command(person)), error => error.status === 403);
  assert.equal((await evidence()).length, 0); assert.equal((await load(person.id)).enabled, true);
});
test('withdrawal of the original bearer after locks or after DML rolls back all child effects', async () => {
  const actor = await admin(); const person = await employee(actor); const body = command(person);
  let checks = 0; const live = { check: async () => { checks++; if (checks === 3) live.withdrawn = true; } };
  await assert.rejects(receive(actor, person, body, database, settings(live)), error => error.status === 401);
  const final = {}; await assert.rejects(receive(actor, person, body, wrapped(async () => { final.withdrawn = true; }), settings(final)), error => error.status === 401);
  assert.deepEqual(await load(person.id), person); assert.equal((await evidence()).length, 0);
});
test('recovery also revalidates current source at pre-commit and never changes the original receipt', async () => {
  const actor = await admin(); const person = await employee(actor); const body = command(person); const first = await receive(actor, person, body); const live = {};
  await assert.rejects(receive(actor, person, body, wrapped(async () => { live.withdrawn = true; }), settings(live)), error => error.status === 401);
  assert.deepEqual(await receive(actor, person, body), first);
});
test('physical commit rejects expired MFA and actual source revocation after all application validations', async () => {
  const actor = await admin(); const person = await employee(actor); const original = actor.user;
  actor.user = { ...original, auth_time: Math.floor(Date.now() / 1000) - 298 };
  actor.user.mfa_authorization = { ...original.mfa_authorization, authTime: actor.user.auth_time };
  const options = settings(); const defer = { ...database, transaction: (operation, settings = {}) => database.transaction(operation, { ...settings,
    beforeCommit: async client => { await settings.beforeCommit?.(client); if (!settings.readOnly) { await client.query("SET LOCAL statement_timeout='15s'"); await client.query('SELECT pg_sleep(2.2)'); } } }) };
  await assert.rejects(receive(actor, person, command(person), defer, options), error => error.code === '42501');
  actor.user = original;
  const revoke = { ...database, transaction: (operation, settings = {}) => database.transaction(operation, { ...settings, beforeCommit: async client => {
    await settings.beforeCommit?.(client); if (!settings.readOnly) {
      const proof = (await client.query("SELECT current_setting('opendirectory.user_mutation') AS proof")).rows[0].proof;
      await client.query("SELECT set_config('opendirectory.user_mutation','',true)");
      await client.query('UPDATE identity_role_assignments SET revoked_at=clock_timestamp() WHERE user_id=$1', [actor.user.identity_authorization.userId]);
      await client.query("SELECT set_config('opendirectory.user_mutation',$1,true)", [proof]);
    }
  } }) };
  await assert.rejects(receive(actor, person, command(person), revoke), error => error.code === '42501');
  assert.deepEqual(await load(person.id), person); assert.equal((await evidence()).length, 0);
});
test('omitted receipt, bridge outbox or mandatory original mutation outbox rolls back the account disable', async () => {
  const actor = await admin(); const person = await employee(actor);
  for (const table of ['identity_company_offboarding_receipts', 'identity_company_offboarding_outbox', 'identity_directory_user_outbox', 'identity_user_outbox', 'identity_company_offboarding_commit_checks']) {
    await pool.query('CREATE FUNCTION offboarding_omit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL;END $$;CREATE TRIGGER zz_offboarding_omit BEFORE INSERT ON ' + table + ' FOR EACH ROW EXECUTE FUNCTION offboarding_omit()');
    try { await assert.rejects(receive(actor, person, command(person))); }
    finally { await pool.query('DROP TRIGGER zz_offboarding_omit ON ' + table + ';DROP FUNCTION offboarding_omit()'); }
    assert.deepEqual(await load(person.id), person); assert.equal((await evidence()).length, 0);
  }
});
test('receipt and actual pending outbox cannot be updated, deleted or truncated, and clearing scope cannot bypass commit', async () => {
  const actor = await admin(); const person = await employee(actor); const body = command(person); await receive(actor, person, body);
  for (const table of ['identity_company_offboarding_receipts', 'identity_company_offboarding_outbox']) {
    for (const sql of ['UPDATE ' + table + ' SET created_at=clock_timestamp()', 'DELETE FROM ' + table, 'TRUNCATE ' + table + ' CASCADE'])
      await assert.rejects(pool.query(sql), error => error.code === '42501');
  }
  const next = await employee(actor);
  await assert.rejects(receive(actor, next, command(next), wrapped(client => client.query("SELECT set_config('opendirectory.company_offboarding','',true)"))), error => error.code === '23514');
  assert.deepEqual(await load(next.id), next); assert.equal((await evidence()).length, 1);
});
test('disabled receiving guards fail before DML and migration replay preserves immutable receipts', async () => {
  const actor = await admin(); const person = await employee(actor);
  for (const [table, trigger] of [['users', 'identity_company_offboarding_commit'], ['identity_company_offboarding_receipts', 'identity_company_offboarding_guard'],
    ['identity_company_offboarding_outbox', 'identity_company_offboarding_commit'], ['identity_company_offboarding_commit_checks', 'identity_company_offboarding_commit']]) {
    await pool.query('ALTER TABLE ' + table + ' DISABLE TRIGGER ' + trigger);
    try { await assert.rejects(receive(actor, person, command(person)), error => error.code === '55000'); }
    finally { await pool.query('ALTER TABLE ' + table + ' ENABLE TRIGGER ' + trigger); }
    assert.deepEqual(await load(person.id), person);
  }
  const body = command(person); const first = await receive(actor, person, body);
  await pool.query(fs.readFileSync(path.join(__dirname, '../../migrations/045_company_offboarding_receipts.sql'), 'utf8'));
  assert.deepEqual(await receive(actor, person, body), first);
  assert.deepEqual((await new CompanyLicenseAuthority(database, settings()).read(actor.user, 'Bearer original', { userId: person.id })).target.eligibilityRevision, first.afterEligibilityRevision);
});
test('parallel lost-response retries serialize to one disable and one immutable receipt', async () => {
  const actor = await admin(); const person = await employee(actor); const body = command(person);
  const results = await Promise.all([receive(actor, person, body), receive(actor, person, body)]);
  assert.deepEqual(results[0], results[1]); assert.equal((await evidence()).length, 1);
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_directory_user_events WHERE id=$1', [results[0].operationId])).rows[0].count, 1);
});

test('receipt recovery has a SQL physical commit deadline even after application checks finish and leaves no retained commit-check rows', async () => {
  const actor = await admin(); const person = await employee(actor); const body = command(person); const first = await receive(actor, person, body);
  const current = actor.user;
  actor.user = { ...current, auth_time: Math.floor(Date.now() / 1000) - 298 };
  actor.user.mfa_authorization = { ...current.mfa_authorization, authTime: actor.user.auth_time };
  const deferred = { ...database, transaction: (operation, options = {}) => database.transaction(operation, { ...options, beforeCommit: async client => {
    await options.beforeCommit?.(client); if (!options.readOnly) { await client.query("SET LOCAL statement_timeout='15s'"); await client.query('SELECT pg_sleep(2.2)'); }
  } }) };
  await assert.rejects(receive(actor, person, body, deferred), error => error.code === '42501');
  actor.user = current;
  const revoked = { ...database, transaction: (operation, options = {}) => database.transaction(operation, { ...options, beforeCommit: async client => {
    await options.beforeCommit?.(client); if (!options.readOnly) await client.query('UPDATE identity_role_assignments SET revoked_at=clock_timestamp() WHERE user_id=$1', [actor.user.identity_authorization.userId]);
  } }) };
  await assert.rejects(receive(actor, person, body, revoked), error => error.code === '42501');
  assert.deepEqual(await receive(actor, person, body), first);
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_company_offboarding_commit_checks')).rows[0].count, 0);
});

test('source withdrawal while the actual target row lock is blocked rejects before any offboarding DML', async () => {
  const actor = await admin(); const person = await employee(actor); const live = {}; const blocker = await pool.connect(); let pending;
  await blocker.query('BEGIN'); await blocker.query('SELECT id FROM users WHERE id=$1 FOR UPDATE', [person.id]);
  try {
    pending = receive(actor, person, command(person), database, settings(live)); pending.catch(() => {}); let waiting = false;
    for (let attempt = 0; attempt < 200; attempt++) {
      waiting = (await pool.query("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'SELECT id FROM users WHERE id=ANY(%ORDER BY id FOR UPDATE') AS waiting")).rows[0].waiting;
      if (waiting) break; await new Promise(resolve => setTimeout(resolve, 5));
    }
    assert.equal(waiting, true); live.withdrawn = true; await blocker.query('COMMIT'); await assert.rejects(pending, error => error.status === 401);
    assert.deepEqual(await load(person.id), person); assert.equal((await evidence()).length, 0);
  } finally { await blocker.query('ROLLBACK'); blocker.release(); await pending?.catch(() => {}); }
});

test('the explicit existing SQL-owner boundary cannot be bypassed by GUCs from a limited login or assumed role', async () => {
  const actor = await admin(); const person = await employee(actor); await receive(actor, person, command(person)); const proof = (await evidence())[0].source;
  const role = 'offboarding_limited_' + randomUUID().replaceAll('-', ''); const password = 'owned-' + randomUUID(); let limited;
  await administration.query(`CREATE ROLE ${role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '${password}'`);
  try {
    await pool.query(`GRANT USAGE ON SCHEMA ${schema} TO ${role};GRANT EXECUTE ON FUNCTION identity_company_offboarding_check(jsonb) TO ${role};GRANT INSERT ON identity_company_offboarding_receipts TO ${role}`);
    const address = new URL(process.env.IDENTITY_TEST_DATABASE_URL); address.username = role; address.password = password;
    limited = new Pool({ connectionString: address.toString(), max: 1, options: '-c search_path=' + schema + ',public' });
    for (const assumed of [false, true]) {
      const client = await (assumed ? pool : limited).connect();
      try {
        await client.query('BEGIN'); if (assumed) await client.query('SET LOCAL ROLE ' + role);
        await client.query("SELECT set_config('opendirectory.company_offboarding',$1,true)", [JSON.stringify(proof)]);
        await assert.rejects(client.query('SELECT identity_company_offboarding_check($1::jsonb)', [JSON.stringify(proof)]), error => error.code === '42501' && error.message.includes('Actual database owner required'));
      } finally { await client.query('ROLLBACK'); client.release(); }
    }
  } finally { await limited?.end(); await pool.query('DROP OWNED BY ' + role); await administration.query('DROP ROLE ' + role); }
  assert.equal((await evidence()).length, 1);
});

test('late SQL receipt substitutions cannot alter original actor or source behind the initial immutable guard', async () => {
  const actor = await admin(); const person = await employee(actor, false);
  for (const change of ['NEW.actor_user_id=gen_random_uuid()', "NEW.source=jsonb_set(NEW.source,'{expectedRevision}',to_jsonb('1'::text))"]) {
    await pool.query('CREATE FUNCTION offboarding_substitute() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN ' + change + ';RETURN NEW;END $$;CREATE TRIGGER zz_offboarding_substitute BEFORE INSERT ON identity_company_offboarding_receipts FOR EACH ROW EXECUTE FUNCTION offboarding_substitute()');
    try { await assert.rejects(receive(actor, person, command(person)), error => error.code === '23514' || error.code === '42501'); }
    finally { await pool.query('DROP TRIGGER zz_offboarding_substitute ON identity_company_offboarding_receipts;DROP FUNCTION offboarding_substitute()'); }
    assert.deepEqual(await load(person.id), person); assert.equal((await evidence()).length, 0);
  }
});

test('real signed JWT HTTP requests reach the real PG bridge, retain immutable receipts and reject changed generations or revoked original proof', async () => {
  const { createServer } = require('node:http');
  const { generateKeyPair, exportJWK, SignJWT, jwtVerify } = require('jose');
  const httpRequest = require('supertest');
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const jwk = { ...await exportJWK(publicKey), kid: 'offboarding-native-key', alg: 'RS256', use: 'sig' };
  const actor = await owner(); const person = await employee(actor); const body = command(person);
  const revoked = new Set(); const observed = []; let tenantChecks = 0; let withdrawAt = Infinity;
  const authority = createServer(async (request, response) => {
    response.setHeader('Content-Type', 'application/json');
    if (request.url === '/jwks') { response.end(JSON.stringify({ keys: [jwk] })); return; }
    try {
      const authorization = request.headers.authorization; assert.match(authorization, /^Bearer /);
      const { payload } = await jwtVerify(authorization.slice(7), publicKey, { issuer, audience: 'opendirectory-api', algorithms: ['RS256'], requiredClaims: ['sub', 'exp', 'iat', 'jti'] });
      observed.push({ path: request.url, authorization });
      if (request.url === '/oauth/tenant-state' && ++tenantChecks === withdrawAt) revoked.add(payload.jti);
      const state = await new AuthorizationState(database).state(payload.iss, payload.sub);
      if (revoked.has(payload.jti) || !state.active || !sameContext(state.context, payload.identity_authorization)) throw new Error('Original proof withdrawn');
      const result = { schemaVersion: 1, active: true, issuer: payload.iss, subject: payload.sub, tokenId: payload.jti, expiresAt: payload.exp };
      if (request.url === '/oauth/tenant-state') Object.assign(result, { context: state.context, tenant: state.tenant });
      else if (request.url !== '/oauth/access-state') throw new Error('Unexpected authority path');
      response.end(JSON.stringify(result));
    } catch { response.statusCode = 401; response.end(JSON.stringify({ schemaVersion: 1, active: false })); }
  });
  await new Promise(resolve => authority.listen(0, '127.0.0.1', resolve));
  const address = 'http://127.0.0.1:' + authority.address().port;
  const environment = { OIDC_ISSUER: issuer, OIDC_AUDIENCE: 'opendirectory-api', JWKS_URI: address + '/jwks',
    OIDC_ACCESS_STATE_URL: address + '/oauth/access-state', OIDC_TENANT_STATE_URL: address + '/oauth/tenant-state' };
  const previous = Object.fromEntries(Object.keys(environment).map(key => [key, process.env[key]])); Object.assign(process.env, environment);
  const sign = (payload, signingKey = privateKey) => new SignJWT({ ...payload, token_use: 'access' }).setProtectedHeader({ alg: 'RS256', kid: jwk.kid })
    .setIssuedAt().setAudience('opendirectory-api').sign(signingKey);
  try {
    const app = require('../index');
    const send = (identity, requestBody, bearer) => httpRequest(app).post(`/api/users/${identity}/company-offboarding`).set('Authorization', 'Bearer ' + bearer).send(requestBody);
    const original = await sign(actor.user); const identityServer = app.listen(0, '127.0.0.1');
    try {
      await new Promise(resolve => identityServer.once('listening', resolve));
      const response = await fetch('http://127.0.0.1:' + identityServer.address().port + '/api/identity/company-blueprints', { headers: { Authorization: 'Bearer ' + original } });
      assert.equal(response.status, 200); assert.equal(response.headers.get('cache-control'), 'no-store');
      const source = await response.json(); assert.equal(validBlueprintSource(source, { ...actor.user, token_use: 'access' }), true);
      assert.equal(Object.keys(source).length, 11); assert.equal(source.tenant.id, actor.tenant); assert.deepEqual(source.permissions, COMPANY_BLUEPRINT_PERMISSIONS);
    } finally { identityServer.closeAllConnections(); await new Promise(resolve => identityServer.close(resolve)); }
    const sourceGet = () => httpRequest(app).get('/api/identity/company-blueprints').set('Authorization', 'Bearer ' + original);
    const assignmentSource = '/api/identity/company-blueprint-assignments';
    const assignmentGet = () => httpRequest(app).get(assignmentSource).set('Authorization', 'Bearer ' + original);
    const assignmentPost = selector => httpRequest(app).post(assignmentSource).set('Authorization', 'Bearer ' + original).send(selector);
    const assignmentActor = await assignmentGet(); assert.equal(assignmentActor.status, 200); assert.equal(assignmentActor.headers['cache-control'], 'no-store');
    assert.equal(validBlueprintAssignmentSource(assignmentActor.body, { ...actor.user, token_use: 'access' }), true); assert.equal(assignmentActor.body.target, null);
    const assignmentTarget = await assignmentPost({ userId: person.id }); assert.equal(assignmentTarget.status, 200);
    assert.equal(validBlueprintAssignmentSource(assignmentTarget.body, { ...actor.user, token_use: 'access' }, person.id), true);
    const assignmentAccount = (await pool.query('SELECT authorization_revision,eligibility_revision FROM users WHERE id=$1', [person.id])).rows[0];
    assert.deepEqual(assignmentTarget.body.target, { id: person.id, revision: String(assignmentAccount.authorization_revision), eligibilityRevision: String(assignmentAccount.eligibility_revision), enabled: true, deleted: false });
    assert.equal((await assignmentGet().send({})).status, 400); assert.equal((await assignmentGet().send([])).status, 400);
    assert.equal((await assignmentGet().query({ userId: person.id })).status, 400); assert.equal((await assignmentGet().set('X-API-Key', '')).status, 400);
    assert.equal((await assignmentPost({ userId: person.id, tenantId: actor.tenant })).status, 400); assert.equal((await assignmentPost({})).status, 400);
    assert.equal((await assignmentPost({ userId: person.id }).set('X-API-Key', '')).status, 400); assert.equal((await assignmentPost({ userId: randomUUID() })).status, 404);
    assert.equal((await sourceGet().send({})).status, 400); assert.equal((await sourceGet().send([])).status, 400);
    assert.equal((await sourceGet().query({ tenantId: randomUUID() })).status, 400); assert.equal((await sourceGet().set('X-API-Key', '')).status, 400);
    const first = await send(person.id, body, original);
    assert.equal(first.status, 200); assert.equal(Object.keys(first.body).length, 13); assert.equal(first.body.action, 'disabled'); assert.equal(first.headers['cache-control'], 'no-store');
    assert.ok(observed.length > 10); assert.equal(observed.every(call => call.authorization === 'Bearer ' + original), true);
    const stale = structuredClone(actor.user); stale.auth_time -= 301; stale.mfa_authorization.authTime -= 301;
    assert.equal((await httpRequest(app).get('/api/identity/company-blueprints').set('Authorization', 'Bearer ' + await sign(stale))).status, 428);
    assert.equal((await httpRequest(app).get(assignmentSource).set('Authorization', 'Bearer ' + await sign(stale))).status, 428);
    const refreshed = await sign({ ...actor.user, jti: randomUUID() }); const recovered = await send(person.id, body, refreshed);
    assert.equal(recovered.status, 200); assert.deepEqual(recovered.body, first.body);
    assert.equal((await send(person.id, { ...body, expectedRevision: (BigInt(body.expectedRevision) + 1n).toString() }, refreshed)).status, 409);
    const mutator = new UserMutator(database, settings()); const disabled = await load(person.id);
    const enabled = await mutator.update(person.id, { enabled: true }, userEtag(disabled), actor.user, 'Bearer original');
    const mutationCount = (await pool.query('SELECT count(*)::int AS count FROM identity_directory_user_events')).rows[0].count;
    assert.equal((await send(person.id, body, refreshed)).status, 409); assert.deepEqual(await load(person.id), enabled);
    assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_directory_user_events')).rows[0].count, mutationCount);
    await mutator.update(person.id, { enabled: false }, userEtag(enabled), actor.user, 'Bearer original');
    assert.equal((await send(person.id, body, refreshed)).status, 409); assert.equal((await evidence()).length, 1);
    const untrusted = await generateKeyPair('RS256'); const forged = await sign(actor.user, untrusted.privateKey);
    assert.equal((await send(person.id, body, forged)).status, 403);
    const next = await employee(actor); const nextBody = command(next); tenantChecks = 0; withdrawAt = 8;
    const withdrawn = await send(next.id, nextBody, original); assert.equal(withdrawn.status, 401); assert.deepEqual(await load(next.id), next);
    assert.equal((await evidence()).length, 1); assert.equal((await send(next.id, nextBody, original)).status, 401);
    assert.equal((await sourceGet()).status, 401);
    assert.equal((await assignmentGet()).status, 401);
    const retained = JSON.stringify(await evidence()); assert.equal(retained.includes(original), false); assert.equal(retained.includes(refreshed), false);
  } finally {
    for (const [key, value] of Object.entries(previous)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; }
    authority.closeAllConnections(); await new Promise(resolve => authority.close(resolve));
  }
});
