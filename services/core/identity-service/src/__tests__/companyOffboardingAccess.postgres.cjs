'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { Pool } = require('pg');
const { CompanyOffboardingAccess } = require('../CompanyOffboardingAccess');
const { CompanyOffboarding } = require('../CompanyOffboarding');
const { AuthorizationState } = require('../AuthorizationState');
const { DirectoryRoles } = require('../DirectoryRoles');
const { PrivilegedActivation } = require('../PrivilegedActivation');
const { DirectoryUsers, userEtag } = require('../DirectoryUsers');
const { UserMutator } = require('../UserMutator');
const { sameContext } = require('../../../../../packages/identity-authorization-contract');
const { PROTECTED } = require('../../../../../packages/directory-role-contract');
const { provisionTenant, adoptTenant } = require('../../../../../scripts/lib/tenant-ownership-fixture.cjs');
const schema = 'offboarding_access_' + randomUUID().replaceAll('-', '');
const issuer = 'https://offboarding-access.test';
const authorization = 'Bearer original-access-' + randomUUID();
const administration = new Pool({ connectionString: process.env.IDENTITY_TEST_DATABASE_URL, max: 1 });
let database; let pool;
before(async () => {
  await administration.query('CREATE SCHEMA ' + schema);
  const address = new URL(process.env.IDENTITY_TEST_DATABASE_URL); address.searchParams.set('options', '-c search_path=' + schema + ',public');
  process.env.DATABASE_URL = address.toString(); database = require('../db'); pool = database.pool;
  assert.equal(await database.initDb(), true);
});
after(async () => { await pool?.end(); await administration.query('DROP SCHEMA ' + schema + ' CASCADE'); await administration.end(); });
async function token(person) {
  const state = await new AuthorizationState(database).state(issuer, person.subject); const now = Math.floor(Date.now() / 1000);
  return { iss: issuer, sub: person.subject, actor_type: 'user', roles: state.roles, identity_authorization: state.context, jti: randomUUID(), exp: now + 600,
    auth_time: now, amr: ['pwd', 'otp'], mfa_authorization: { schemaVersion: 1, userId: person.id, revision: '1', authTime: now, methods: ['pwd', 'otp'] } };
}
function settings(live = {}) {
  return { issuer, revalidate: async (bearer, user) => {
    assert.equal(bearer, authorization); await live.check?.();
    const state = await new AuthorizationState(database).state(issuer, user.sub);
    if (live.withdrawn || !state.active || !sameContext(state.context, user.identity_authorization)) throw Object.assign(new Error('Original source withdrawn'), { status: 401 });
    return state.tenant;
  } };
}
async function person(tenant, role) {
  tenant ||= await provisionTenant(database, schema, { enabled: true }); const id = randomUUID(); const subject = 'access-' + id;
  await pool.query('INSERT INTO users(id,username,email) VALUES($1,$2,$3)', [id, subject, subject + '@test.invalid']);
  await pool.query('INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES($1,$2,$3)', [issuer, subject, id]);
  await adoptTenant(database, schema, tenant, [{ kind: 'user', resourceId: id }]);
  if (role) await pool.query('INSERT INTO identity_role_assignments(user_id,role,reason) VALUES($1,$2,$3)', [id, role, 'Explicit canonical cleanup operator fixture']);
  const created = { id, subject, tenant }; return { ...created, user: await token(created) };
}
async function fixture(kind = 'role', operatorRole = kind === 'role' ? 'role-administrator' : 'pim-administrator', count = 2, grantRole = 'directory-reader', prepare) {
  const admin = await person(undefined, 'admin'); const target = await person(admin.tenant); const operator = operatorRole === 'admin' ? admin : await person(admin.tenant, operatorRole);
  const options = { revalidate: (user, bearer) => settings().revalidate(bearer, user) };
  for (let index = 0; index < count; index++) {
    if (kind === 'role') await new DirectoryRoles(database, options).grant(target.id, { role: grantRole, durationSeconds: 3600, reason: 'Explicit retained employee role grant fixture' }, admin.user, authorization);
    else await new PrivilegedActivation(database, options).grantEligibility({ userId: target.id, role: grantRole, maxDurationSeconds: 600, validForSeconds: 3600, reason: 'Explicit retained employee eligibility grant fixture' }, admin.user, authorization);
  }
  await prepare?.({ admin, target, options });
  const account = await new DirectoryUsers(database).get(target.id);
  const parent = await new CompanyOffboarding(database, settings()).receive(target.id, { workflowId: randomUUID(), expectedRevision: account.revision, confirm: true }, admin.user, authorization);
  const service = new CompanyOffboardingAccess(database, settings());
  const selectors = { workflowId: parent.workflowId, kind };
  const preview = await service.preview(target.id, selectors, operator.user, authorization);
  const intent = { workflowId: parent.workflowId, eligibilityRevision: parent.afterEligibilityRevision, kind, reason: 'Remove captured original employee access grants', confirm: true,
    items: preview.items.map(({ id, version }) => ({ id, version })) };
  return { admin, target, operator, parent, preview, selectors, intent };
}
const revoke = (value, db = database, options = settings()) => new CompanyOffboardingAccess(db, options).revoke(value.target.id, value.intent, value.operator.user, authorization);
async function receipts(value) { return (await pool.query('SELECT * FROM identity_company_offboarding_access_receipts WHERE workflow_id=$1 ORDER BY created_at,id', [value.parent.workflowId])).rows; }
function wrapped({ beforeCommit, afterCommit, query, onError, atStart } = {}) {
  return { ...database, transaction: async (operation, options = {}) => {
    const result = await database.transaction(async client => { await atStart?.(client); return operation({ query: (sql, values) => query ? query(client, sql, values) : client.query(sql, values) }); },
      { ...options, beforeCommit: async client => { await options.beforeCommit?.(client); if (!options.readOnly) await beforeCommit?.(client); } }).catch(error => { onError?.(error); throw error; });
    if (!options.readOnly) await afterCommit?.(result); return result;
  } };
}

test('native non-owner role operator removes two grants with original canonical checkpoints and pending atomic receipts', async () => {
  const value = await fixture(); let childError;
  const result = await revoke(value, wrapped({ onError: error => { childError = error; } }));
  assert.deepEqual(result.results.map(item => item.status), ['revoked', 'revoked'], childError?.stack + '\n' + childError?.where);
  const rows = await receipts(value); assert.equal(rows.length, 2);
  for (const row of rows) {
    await pool.query('SELECT identity_company_offboarding_access_validate($1)', [row.id]);
    assert.equal(row.before_state.grant.revoked_at, null); assert.ok(row.after_state.grant.revoked_at);
    assert.equal(row.role_audit.length, 1); assert.equal(row.pim_audit.length, 0);
    assert.equal(row.actor_user_id, value.operator.id); assert.equal(row.eligibility_revision, value.parent.afterEligibilityRevision);
    assert.ok(!JSON.stringify(row).includes(authorization)); assert.ok(!JSON.stringify(row).includes(value.operator.user.jti));
  }
  assert.deepEqual(Object.keys(result), ['schemaVersion', 'actorUserId', 'tenantId', 'workflowId', 'userId', 'kind', 'correlationId', 'results']);
  const history = await new CompanyOffboardingAccess(database, settings()).history(value.target.id, value.selectors, value.operator.user, authorization);
  assert.equal(history.total, 2); assert.ok(history.receipts.every(item => item.deliveryStatus === 'pending'));
});

test('native independent PIM-only operator revokes actual eligibility without role-admin or company-owner permission', async () => {
  const value = await fixture('eligibility'); let childError;
  const result = await revoke(value, wrapped({ onError: error => { childError = error; } }));
  assert.deepEqual(result.results.map(item => item.status), ['revoked', 'revoked'], childError?.stack + '\n' + childError?.where);
  for (const row of await receipts(value)) { assert.equal(row.role_audit.length, 0); assert.equal(row.pim_audit.length, 1); await pool.query('SELECT identity_company_offboarding_access_validate($1)', [row.id]); }
});

test('capabilities and read-only rows require only corresponding actual canonical read duty', async () => {
  const value = await fixture('role', 'role-reader'); const service = new CompanyOffboardingAccess(database, settings());
  const capabilities = await service.capabilities(value.target.id, { workflowId: value.parent.workflowId }, value.operator.user, authorization);
  assert.deepEqual(capabilities.permissions, ['identities.roles.read']); assert.deepEqual(capabilities.supportedKinds, ['role']);
  assert.equal(value.preview.canRevoke, false); assert.ok(value.preview.items.every(item => !item.canRevoke && item.blockedReason === 'permission_required'));
  await assert.rejects(revoke(value), error => error.status === 403);
  await assert.rejects(service.preview(value.target.id, { ...value.selectors, kind: 'eligibility' }, value.operator.user, authorization), error => error.status === 403);
  assert.equal((await receipts(value)).length, 0);
});

test('real protected role preflight requires canonical admin and SQL protected catalog matches shared kernel contract', async () => {
  const value = await fixture('role', 'role-administrator', 1, 'admin');
  assert.equal(value.preview.items[0].blockedReason, 'protected_role');
  await assert.rejects(revoke(value), error => error.status === 403);
  assert.deepEqual((await pool.query('SELECT identity_company_offboarding_access_protected() AS roles')).rows[0].roles, [...PROTECTED]);
  value.operator = value.admin; assert.equal((await revoke(value)).results[0].status, 'revoked');
});

test('whole manifest stale later item rejects before the first canonical write', async () => {
  const value = await fixture(); value.intent.items[1].version = '0'.repeat(64);
  await assert.rejects(revoke(value), error => error.status === 412); assert.equal((await receipts(value)).length, 0);
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_role_assignments WHERE user_id=$1 AND revoked_at IS NULL', [value.target.id])).rows[0].count, 2);
});

test('lost ACK stops the manifest; explicit old-ID/version recovery keeps new grant UUID untouched', async () => {
  const value = await fixture(); let lost = false;
  const result = await revoke(value, wrapped({ afterCommit: async () => { if (!lost) { lost = true; throw new Error('Lost COMMIT acknowledgement'); } } }));
  assert.deepEqual(result.results.map(item => item.status), ['unconfirmed', 'not_attempted']); assert.equal(result.results[0].checkpointId, null);
  const original = (await receipts(value))[0];
  const options = { revalidate: (user, bearer) => settings().revalidate(bearer, user) };
  const newGrant = await new DirectoryRoles(database, options).grant(value.target.id, { role: 'directory-reader', durationSeconds: 3600, reason: 'Independent new access grant after original cleanup' }, value.admin.user, authorization);
  const recovered = await revoke(value);
  assert.deepEqual(recovered.results.map(item => item.status), ['already_revoked', 'revoked']); assert.equal(recovered.results[0].checkpointId, original.checkpoint_id);
  assert.equal((await pool.query('SELECT revoked_at FROM identity_role_assignments WHERE id=$1', [newGrant.id])).rows[0].revoked_at, null);
  assert.equal((await receipts(value)).length, 2);
});

test('wrong parent, self and changed negative epoch fail without exposing grants', async () => {
  const value = await fixture(); const service = new CompanyOffboardingAccess(database, settings());
  await assert.rejects(service.preview(value.operator.id, value.selectors, value.operator.user, authorization), error => error.status === 403);
  await assert.rejects(service.preview(value.target.id, { ...value.selectors, workflowId: randomUUID() }, value.operator.user, authorization), error => error.status === 409);
  await assert.rejects(service.preview(value.admin.id, value.selectors, value.operator.user, authorization), error => error.status === 409);
  value.intent.eligibilityRevision = '9223372036854775807'; await assert.rejects(revoke(value), error => error.status === 409);
  assert.equal((await receipts(value)).length, 0);
});

test('expired independent MFA is rejected even when the role policy does not require recent MFA', async () => {
  const value = await fixture(); value.operator.user.auth_time -= 301; value.operator.user.mfa_authorization.authTime -= 301;
  await assert.rejects(revoke(value), error => error.status === 428); assert.equal((await receipts(value)).length, 0);
});

test('canonical actor withdrawal after preflight withholds result and makes no new grants', async () => {
  const value = await fixture(); const state = { withdrawn: false }; let writes = 0;
  const observed = wrapped({ query: async (client, sql, parameters) => { if (sql.startsWith('SELECT identity_company_offboarding_access_begin')) { writes++; state.withdrawn = true; } return client.query(sql, parameters); } });
  await assert.rejects(revoke(value, observed, settings(state)), error => error.status === 401); assert.equal((await receipts(value)).length, 0); assert.equal(writes, 1);
});

test('physical missing pending child outbox rolls back native revocation and canonical checkpoint', async () => {
  const value = await fixture();
  await pool.query('CREATE FUNCTION omit_access_outbox() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL;END;$$;CREATE TRIGGER zzz_omit_access_outbox BEFORE INSERT ON identity_company_offboarding_access_outbox FOR EACH ROW EXECUTE FUNCTION omit_access_outbox()');
  try { const result = await revoke(value); assert.equal(result.results[0].status, 'unconfirmed'); assert.equal((await receipts(value)).length, 0); }
  finally { await pool.query('DROP TRIGGER zzz_omit_access_outbox ON identity_company_offboarding_access_outbox;DROP FUNCTION omit_access_outbox()'); }
  assert.equal((await pool.query('SELECT revoked_at FROM identity_role_assignments WHERE id=$1', [value.intent.items[0].id])).rows[0].revoked_at, null);
});

test('receipt and source evidence are immutable and migration replay retains real receipts', async () => {
  const value = await fixture('role', 'admin', 1); assert.equal((await revoke(value)).results[0].status, 'revoked');
  const rows = await receipts(value);
  for (const sql of ['UPDATE identity_company_offboarding_access_receipts SET reason=reason', 'DELETE FROM identity_company_offboarding_access_checks', 'DELETE FROM identity_company_offboarding_access_outbox'])
    await assert.rejects(pool.query(sql), error => error.code === '42501');
  const fs = require('node:fs'); const path = require('node:path'); await pool.query(fs.readFileSync(path.join(__dirname, '../../migrations/047_company_offboarding_access.sql'), 'utf8'));
  assert.deepEqual(await receipts(value), rows); await pool.query('SELECT identity_company_offboarding_access_validate($1)', [rows[0].id]);
});

test('existing revokeEligibility performs pending request cancellation with actual canonical PIM audits', async () => {
  let requestId;
  const value = await fixture('eligibility', 'pim-administrator', 1, 'directory-reader', async ({ target, options }) => {
    const eligibility = (await pool.query('SELECT id FROM identity_pim_eligibilities WHERE user_id=$1', [target.id])).rows[0]; requestId = randomUUID();
    await new PrivilegedActivation(database, options).request({ id: requestId, eligibilityId: eligibility.id, durationSeconds: 300, reason: 'Actual pending request before employee disable' }, target.user, authorization);
  });
  let childError; const result = await revoke(value, wrapped({ onError: error => { childError = error; } }));
  assert.equal(result.results[0].status, 'revoked', childError?.stack + '\n' + childError?.where);
  assert.equal((await pool.query('SELECT state FROM identity_pim_requests WHERE id=$1', [requestId])).rows[0].state, 'cancelled');
  const row = (await receipts(value))[0]; assert.equal(row.pim_audit.length, 2); assert.equal(row.role_audit.length, 0);
});

test('existing revokeEligibility actually cascades active assignment and request with original checkpoint', async () => {
  let requestId; let assignmentId;
  const value = await fixture('eligibility', 'pim-administrator', 1, 'directory-reader', async ({ admin, target, options }) => {
    const eligibility = (await pool.query('SELECT id FROM identity_pim_eligibilities WHERE user_id=$1', [target.id])).rows[0]; requestId = randomUUID(); const pim = new PrivilegedActivation(database, options);
    await pim.request({ id: requestId, eligibilityId: eligibility.id, durationSeconds: 300, reason: 'Actual activation before employee disable fixture' }, target.user, authorization);
    await pim.change(requestId, 'approve', admin.user, authorization); const active = await pim.change(requestId, 'activate', target.user, authorization); assignmentId = active.assignmentId;
  });
  let childError; const result = await revoke(value, wrapped({ onError: error => { childError = error; } }));
  assert.equal(result.results[0].status, 'revoked', childError?.stack + '\n' + childError?.where);
  assert.equal((await pool.query('SELECT state FROM identity_pim_requests WHERE id=$1', [requestId])).rows[0].state, 'revoked');
  assert.ok((await pool.query('SELECT revoked_at FROM identity_role_assignments WHERE id=$1', [assignmentId])).rows[0].revoked_at);
  const row = (await receipts(value))[0]; assert.equal(row.pim_audit.length, 2); assert.equal(row.role_audit.length, 1); assert.equal(row.authorization_audit.length, 1); assert.equal(row.record_audit.length, 1);
  await pool.query('SELECT identity_company_offboarding_access_validate($1)', [row.id]);
});

test('malformed imported foreign activation link rejects the full manifest without touching any grant', async () => {
  let foreign; let requestId;
  const value = await fixture('eligibility', 'pim-administrator', 2, 'directory-reader', async ({ target, options }) => {
    foreign = await person(undefined); const eligibility = (await pool.query('SELECT id FROM identity_pim_eligibilities WHERE user_id=$1 ORDER BY created_at,id DESC LIMIT 1', [target.id])).rows[0]; requestId = randomUUID();
    await new PrivilegedActivation(database, options).request({ id: requestId, eligibilityId: eligibility.id, durationSeconds: 300, reason: 'Malformed imported foreign request fixture source' }, target.user, authorization);
    await pool.query('ALTER TABLE identity_pim_requests DISABLE TRIGGER USER');
    try { await pool.query('UPDATE identity_pim_requests SET user_id=$2 WHERE id=$1', [requestId, foreign.id]); }
    finally { await pool.query('ALTER TABLE identity_pim_requests ENABLE TRIGGER USER'); }
  });
  await assert.rejects(revoke(value), error => error.code === '23514'); assert.equal((await receipts(value)).length, 0);
  assert.equal((await pool.query('SELECT user_id,state FROM identity_pim_requests WHERE id=$1', [requestId])).rows[0].user_id, foreign.id);
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_pim_eligibilities WHERE user_id=$1 AND revoked_at IS NULL', [value.target.id])).rows[0].count, 2);
});

test('raw valid non-admin source cannot begin protected cleanup despite existing SQL kernel not enforcing JS catalog', async () => {
  const value = await fixture('role', 'admin', 1, 'admin'); assert.equal((await revoke(value)).results[0].status, 'revoked');
  const receipt = (await receipts(value))[0]; const operator = await person(value.admin.tenant, 'role-administrator');
  const state = (await pool.query('SELECT identity_subject_link_role_state($1) AS state', [operator.id])).rows[0].state;
  const proof = { ...receipt.source, context: operator.user.identity_authorization, subject: operator.subject, rolesSnapshot: state, recovery: true, authTime: operator.user.auth_time,
    validUntil: operator.user.auth_time + 300, correlationId: randomUUID() };
  await assert.rejects(database.transaction(client => client.query('SELECT identity_company_offboarding_access_begin($1::jsonb)', [JSON.stringify(proof)])), error => error.code === '42501');
  assert.equal((await receipts(value)).length, 1);
});

test('physical cleanup assurance expiry after application beforeCommit rolls back the actual native child', async () => {
  const value = await fixture('role', 'role-administrator', 1);
  value.operator.user.auth_time -= 296; value.operator.user.mfa_authorization.authTime -= 296;
  let childError; let reachedCommit = false;
  const result = await revoke(value, wrapped({ onError: error => { childError ||= error; }, beforeCommit: async client => { reachedCommit = true; await client.query("SET LOCAL statement_timeout='8s'"); await client.query('SELECT pg_sleep((GREATEST(0,$1::numeric-extract(epoch FROM clock_timestamp()))+0.05)::double precision)', [value.operator.user.auth_time + 300]); } })).catch(error => error);
  assert.ok([401, 428].includes(result.status), JSON.stringify(result) + '\n' + childError?.stack + '\n' + childError?.where); assert.ok(reachedCommit); assert.equal(childError?.code, '28000'); assert.equal((await receipts(value)).length, 0);
  assert.equal((await pool.query('SELECT revoked_at FROM identity_role_assignments WHERE id=$1', [value.intent.items[0].id])).rows[0].revoked_at, null);
});

test('expired but unrevoked stored roles stay visible and removable without claiming active authority', async () => {
  const value = await fixture('role', 'role-administrator', 0, 'directory-reader', async ({ target }) => {
    await pool.query("INSERT INTO identity_role_assignments(user_id,role,reason,expires_at) VALUES($1,'directory-reader','Actual expired stored grant retained for cleanup',clock_timestamp()+interval '1 millisecond')", [target.id]);
  });
  assert.equal(value.preview.items.length, 1); assert.ok(new Date(value.preview.items[0].expiresAt) < new Date());
  assert.equal((await revoke(value)).results[0].status, 'revoked');
});

test('independent page of 25 leaves unseen 26th real grant UUID and canonical row version untouched', async () => {
  const value = await fixture('role', 'role-administrator', 26); assert.equal(value.preview.total, 26); assert.equal(value.intent.items.length, 25);
  const service = new CompanyOffboardingAccess(database, settings()); const second = await service.preview(value.target.id, { ...value.selectors, page: '2', limit: '25' }, value.operator.user, authorization);
  const untouched = second.items[0]; const beforeRow = (await pool.query('SELECT * FROM identity_role_assignments WHERE id=$1', [untouched.id])).rows[0];
  const result = await revoke(value); assert.equal(result.results.length, 25); assert.ok(result.results.every(item => item.status === 'revoked')); assert.equal((await receipts(value)).length, 25);
  assert.deepEqual((await pool.query('SELECT * FROM identity_role_assignments WHERE id=$1', [untouched.id])).rows[0], beforeRow);
  const remaining = await service.preview(value.target.id, value.selectors, value.operator.user, authorization); assert.equal(remaining.total, 1); assert.deepEqual(remaining.items, [untouched]);
});

test('changed receiving hook fails closed before writes and canonical grants remain intact', async () => {
  const value = await fixture('role', 'role-administrator', 1);
  await pool.query('ALTER TABLE identity_company_offboarding_access_receipts DISABLE TRIGGER aaa_identity_authority_stage_no_effects');
  try { await assert.rejects(revoke(value), error => error.code === '55000'); }
  finally { await pool.query('ALTER TABLE identity_company_offboarding_access_receipts ENABLE TRIGGER aaa_identity_authority_stage_no_effects'); }
  assert.equal((await receipts(value)).length, 0);
});

test('reactivation and later redisabling cannot reuse the original negative parent checkpoint', async () => {
  const value = await fixture('role', 'role-administrator', 1); const mutator = new UserMutator(database, settings());
  const account = await new DirectoryUsers(database).get(value.target.id);
  const reactivated = await mutator.update(value.target.id, { enabled: true }, userEtag(account), value.admin.user, authorization);
  await assert.rejects(revoke(value), error => error.status === 409);
  await mutator.update(value.target.id, { enabled: false }, userEtag(reactivated), value.admin.user, authorization);
  await assert.rejects(revoke(value), error => error.status === 409); assert.equal((await receipts(value)).length, 0);
});

test('ordinary DML cannot invent an unrevoked before-state for an already revoked grant', async () => {
  const value = await fixture('role', 'role-administrator', 1); assert.equal((await revoke(value)).results[0].status, 'revoked');
  const receipt = (await receipts(value))[0]; const proof = { ...receipt.source, receiptId: randomUUID(), correlationId: randomUUID() };
  await assert.rejects(database.transaction(async client => {
    await client.query("SELECT set_config('opendirectory.company_offboarding_access',$1,true)", [JSON.stringify(proof)]);
    await client.query('INSERT INTO identity_company_offboarding_access_checks(source,before_state) SELECT $1::jsonb,before_state FROM identity_company_offboarding_access_receipts WHERE id=$2', [JSON.stringify(proof), receipt.id]);
  }), error => error.code === '23514');
  assert.equal((await receipts(value)).length, 1);
});

test('SQL row SHA256 is exact at large policy versions and non-UTC session timezone', async () => {
  const value = await fixture('role', 'role-administrator', 0, 'directory-reader', async ({ target }) => {
    await pool.query('ALTER TABLE identity_role_activation_policies DISABLE TRIGGER USER');
    try { await pool.query("UPDATE identity_role_activation_policies SET version=9007199254740993 WHERE role='directory-reader'"); }
    finally { await pool.query('ALTER TABLE identity_role_activation_policies ENABLE TRIGGER USER'); }
    await pool.query("INSERT INTO identity_role_assignments(user_id,role,reason) VALUES($1,'directory-reader','Large actual canonical role policy version fixture')", [target.id]);
  });
  assert.equal((await pool.query('SELECT policy_version FROM identity_role_assignments WHERE id=$1', [value.intent.items[0].id])).rows[0].policy_version, '9007199254740993');
  const service = new CompanyOffboardingAccess(wrapped({ atStart: client => client.query("SET LOCAL timezone='Pacific/Honolulu'") }), settings());
  const preview = await service.preview(value.target.id, value.selectors, value.operator.user, authorization);
  const actual = await database.transaction(async client => { await client.query("SET LOCAL timezone='UTC'"); return (await client.query("SELECT identity_authority_hash(to_jsonb(grant_row)) AS version FROM identity_role_assignments grant_row WHERE id=$1", [value.intent.items[0].id])).rows[0].version; }, { readOnly: true });
  assert.equal(preview.items[0].version, actual); assert.equal((await revoke(value)).results[0].status, 'revoked');
});
