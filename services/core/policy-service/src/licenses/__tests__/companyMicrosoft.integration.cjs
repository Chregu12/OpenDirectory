'use strict';

const { test, beforeEach, afterEach, after } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID, randomBytes } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { Pool } = require('pg');
const { LicenseAllocator } = require('../LicenseAllocator');
const { CompanyLicenses } = require('../CompanyLicenses');
const { CompanyMicrosoftBridge } = require('../CompanyMicrosoftBridge');
const { CompanyMicrosoftDelivery } = require('../CompanyMicrosoftDelivery');
const { COMPANY_LICENSE_PERMISSIONS } = require('../../../../../../packages/company-license-contract');
const express = require('express'); const request = require('supertest');

const admin = new Pool({ connectionString: process.env.LICENSE_TEST_DATABASE_URL, max: 1 });
let pool, schema, database, source, user, target, companies, bridge, sku, remoteId, calls, delayCommit, targetState, observed, writes, writeHandler, permits;
beforeEach(async () => {
  schema = 'company_microsoft_' + randomUUID().replaceAll('-', ''); await admin.query('CREATE SCHEMA ' + schema);
  pool = new Pool({ connectionString: process.env.LICENSE_TEST_DATABASE_URL, options: '-c search_path=' + schema + ',public', max: 5 });
  for (const name of fs.readdirSync(path.join(__dirname, '../../db/migrations')).filter(value => value.endsWith('.sql')).sort()) await pool.query(fs.readFileSync(path.join(__dirname, '../../db/migrations', name), 'utf8'));
  delayCommit = null;
  database = { query: (...args) => pool.query(...args), getClient: async () => {
    const client = await pool.connect(); return { query: async (...args) => {
      if (String(args[0]).includes('SELECT company_microsoft_prepare(')) permits.push(args[1][2]);
      if (args[0] === 'COMMIT' && delayCommit) await delayCommit(); return client.query(...args);
    }, release: destroy => client.release(destroy) };
  } };
  const now = Math.floor(Date.now() / 1000), actor = randomUUID(); target = randomUUID(); remoteId = randomUUID(); calls = [];
  user = { actor_type: 'user', token_use: 'access', iss: 'https://company-microsoft.fixture', sub: 'explicit-company-owner', jti: randomUUID(), auth_time: now, exp: now + 3600,
    identity_authorization: { userId: actor, revision: '1', linkRevision: '1', rolesRevision: 'a'.repeat(64) }, amr: ['pwd', 'otp'],
    mfa_authorization: { schemaVersion: 1, userId: actor, revision: '1', authTime: now, methods: ['pwd', 'otp'] } };
  source = { schemaVersion: 1, issuer: user.iss, subject: user.sub, tokenId: user.jti, expiresAt: user.exp, context: user.identity_authorization,
    actorUserId: actor, tenant: { id: randomUUID(), version: '1', generation: '1' }, permissions: [...COMPANY_LICENSE_PERMISSIONS], validUntil: now + 300, target: null };
  targetState = { revision: '1', eligibilityRevision: '1', enabled: true, deleted: false };
  observed = { present: false, direct: false, active: false, plansMatch: false, inherited: false, accountEnabled: true };
  writes = []; writeHandler = null; permits = [];
  const authority = { read: async (_authorization, _user, requested = null) => {
    if (requested !== null && requested !== target) throw Object.assign(new Error('Own target required'), { status: 404 });
    return structuredClone({ ...source, target: requested === null ? null : { id: target, ...targetState } });
  } };
  const allocator = new LicenseAllocator(database); companies = new CompanyLicenses(allocator, { authority });
  companies.sourceOptions.assignmentAuthority = { read: async (...args) => ({ ...await authority.read(...args), companyBlueprintAssignmentsProtocol: 1, permissions: ['company.blueprints.assignments.read', 'company.blueprints.assign'] }) };
  sku = { skuId: randomUUID(), skuPartNumber: 'BUSINESS', appliesTo: 'User', capabilityStatus: 'Enabled', prepaidUnits: { enabled: 10, warning: 0, suspended: 0, lockedOut: 0 }, consumedUnits: 1 };
  const tenantId = randomUUID(), readId = randomUUID(), writeId = randomUUID();
  bridge = new CompanyMicrosoftBridge(companies, { tenantId: source.tenant.id, readFilename: 'read.fixture', writeFilename: 'write.fixture',
    load: name => ({ schemaVersion: 1, provider: 'microsoft-365', tenantId, clientId: name === 'read.fixture' ? readId : writeId, clientSecret: 'explicit-fixture-secret', consentReviewed: true }),
    createReader: () => ({ inspect: async () => { calls.push('capacity'); return [structuredClone(sku)]; } }),
    createGraph: config => ({ tenantId: config.tenantId, tokens: { get: async () => 'fixture-ms-access-token', clear: () => {} },
      mutate: async (id, product, plans, desired, token, operation) => {
        assert.equal(id, remoteId); assert.equal(product, sku.skuId); assert.deepEqual(plans, []); assert.equal(token, 'fixture-ms-access-token');
        writes.push({ id, product, desired, operation });
        if (writeHandler) return writeHandler(desired, operation);
        observed = { present: desired, direct: desired, active: desired, plansMatch: desired, inherited: false, accountEnabled: true };
      }, readUser: async id => { calls.push(id); return { id, accountEnabled: true }; }, inspect: async (id, product) => {
      assert.equal(id, remoteId); assert.equal(product, sku.skuId); calls.push('inspect'); return structuredClone(observed);
    } }),
  });
});
afterEach(async () => { await pool.end(); await admin.query('DROP SCHEMA ' + schema + ' CASCADE'); });
after(async () => admin.end());
const input = () => ({ reason: 'Explicit native company Microsoft binding review', confirm: true });
const connectionInput = () => { const config = bridge.configurations(source); return { ...input(), microsoftTenantId: config.read.tenantId, readClientId: config.read.clientId, writeClientId: config.write.clientId }; };
const connect = () => bridge.connect(connectionInput(), randomUUID(), user, 'Bearer explicit-company-fixture');
const connectionVersion = async (revision = '1') => ({ id: (await bridge.state(user, 'Bearer explicit-company-fixture')).connection.id, revision });
const createPool = () => companies.create({ name: 'Native Microsoft pool', vendor: 'Microsoft', description: '', totalSeats: 2, reason: 'Actual company catalog fixture' }, user, 'Bearer explicit-company-fixture');
async function mappedPool() {
  const local = await createPool(); await connect();
  await bridge.bindPool(local.id, { ...input(), skuId: sku.skuId, exclusiveDirectManagement: true }, await connectionVersion(), randomUUID(), user, 'Bearer explicit-company-fixture');
  await bridge.bindUser(target, { ...input(), objectId: remoteId, exclusiveDirectManagement: true }, await connectionVersion(), randomUUID(), user, 'Bearer explicit-company-fixture');
  return local;
}
async function manual(poolId, remove = false) {
  const before = await companies.v2.assignmentPreview(poolId, { userId: target }, user, 'Bearer explicit-company-fixture');
  const body = { ...input(), userId: target, eligibilityRevision: targetState.eligibilityRevision, sources: before.assignment?.sources || [], ...(!remove ? { assignmentId: before.assignment?.id || null } : {}) };
  return remove ? companies.v2.revoke(poolId, before.assignment.id, body, `"company-pool-${poolId}-${before.poolRevision}"`, randomUUID(), user, 'Bearer explicit-company-fixture')
    : companies.v2.assign(poolId, body, `"company-pool-${poolId}-${before.poolRevision}"`, randomUUID(), user, 'Bearer explicit-company-fixture');
}
const syncInput = preview => ({ ...input(), fingerprint: preview.fingerprint, action: preview.action });
async function sync(delivery, poolId, operation = randomUUID(), preview = null) {
  preview ||= await delivery.preview(poolId, target, user, 'Bearer explicit-company-fixture');
  return delivery.sync(poolId, target, syncInput(preview), operation, user, 'Bearer explicit-company-fixture');
}

async function interrupted(delivery, poolId, phase) {
  const preview = await delivery.preview(poolId, target, user, 'Bearer explicit-company-fixture');
  const { fingerprint, action, checkedAt, ...capture } = preview;
  const authority = await companies.authority.read('Bearer explicit-company-fixture', user, target);
  const operation = randomUUID(), nonce = randomBytes(32).toString('hex'); const client = await pool.connect();
  try {
    const bindings = await delivery.bindings(client, poolId, authority, bridge.requireConfiguration(authority));
    const projection = await delivery.projection(client, poolId, authority, 'Bearer explicit-company-fixture');
    await delivery.transaction(client, () => client.query('SELECT company_microsoft_prepare($1,$2,$3,$4,$5,$6,$7)', [authority, operation, nonce, bindings.id, { ...syncInput(preview), poolId, userId: target }, projection, capture]));
    if (phase === 'dispatched') await delivery.transaction(client, () => client.query('SELECT company_microsoft_dispatch($1,$2)', [operation, nonce]));
    return { operation, nonce, targetId: bindings.id, source: authority, preview };
  } finally { client.release(); }
}
const recoveryInput = review => ({ ...input(), fingerprint: review.fingerprint, interruptedOperationId: review.attempt.id, interruptedPhase: review.attempt.phase });
const reviewInput = (review, decision) => ({ ...input(), fingerprint: review.fingerprint, uncertainOperationId: review.attempt.id, decision });
async function unknownAddition(poolId, apply = true) {
  const { ProviderError } = require('../fulfillment/transport'); const delivery = new CompanyMicrosoftDelivery(bridge);
  writeHandler = async desired => {
    if (apply) observed = { present: desired, direct: desired, active: desired, plansMatch: desired, inherited: false, accountEnabled: true };
    throw new ProviderError('graph_write_unavailable', { uncertain: true });
  };
  const before = await delivery.preview(poolId, target, user, 'Bearer explicit-company-fixture'); const operation = randomUUID();
  await sync(delivery, poolId, operation, before); return { delivery, before, operation };
}
async function settleReview(review) {
  const delay = Math.max(0, Date.parse(review.attempt.notBefore) - Date.now() + 40); assert.ok(delay <= 31000);
  if (delay) await new Promise(resolve => setTimeout(resolve, delay));
}

test('explicit review adopts only its matching uncertain addition and keeps the original unknown outcome immutable', async () => {
  const local = await mappedPool(); await manual(local.id); const { delivery, before, operation } = await unknownAddition(local.id);
  const original = (await pool.query('SELECT * FROM company_microsoft_operations WHERE id=$1', [operation])).rows[0];
  const review = await delivery.reviewPreview(local.id, target, user, 'Bearer explicit-company-fixture'); assert.deepEqual(review.decisions, ['adopt', 'release']);
  await assert.rejects(delivery.review(local.id, target, reviewInput(review, 'adopt'), randomUUID(), user, 'Bearer explicit-company-fixture'), error => error.status === 409); await settleReview(review);
  const held = await pool.connect();
  try {
    await held.query('SELECT pg_advisory_lock(hashtextextended($1,0))', ['company-microsoft:' + review.target.id]);
    await assert.rejects(delivery.review(local.id, target, reviewInput(review, 'adopt'), randomUUID(), user, 'Bearer explicit-company-fixture'), error => error.status === 409);
  } finally { await held.query('SELECT pg_advisory_unlock(hashtextextended($1,0))', ['company-microsoft:' + review.target.id]); held.release(); }
  observed.active = false;
  await assert.rejects(delivery.review(local.id, target, reviewInput(review, 'adopt'), randomUUID(), user, 'Bearer explicit-company-fixture'), error => error.status === 412); observed.active = true;
  await pool.query("CREATE FUNCTION suppress_review_target() RETURNS TRIGGER LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$; CREATE TRIGGER suppress_review_target BEFORE UPDATE ON company_microsoft_targets FOR EACH ROW EXECUTE FUNCTION suppress_review_target()");
  await assert.rejects(delivery.review(local.id, target, reviewInput(review, 'adopt'), randomUUID(), user, 'Bearer explicit-company-fixture'), error => error.code === '42501');
  await pool.query('DROP TRIGGER suppress_review_target ON company_microsoft_targets; DROP FUNCTION suppress_review_target()');
  const key = randomUUID(), body = reviewInput(review, 'adopt'); const adopted = await delivery.review(local.id, target, body, key, user, 'Bearer explicit-company-fixture');
  assert.equal(adopted.result.status, 'confirmed'); assert.equal(adopted.result.owned, true); assert.equal(adopted.result.uncertainOperationIdAfter, null); assert.equal(adopted.result.uncertainOperationId, operation); assert.equal(writes.length, 1);
  assert.deepEqual((await pool.query('SELECT * FROM company_microsoft_operations WHERE id=$1', [operation])).rows[0], original);
  assert.equal((await sync(delivery, local.id, operation, before)).result.kind, 'unknown'); assert.equal((await sync(delivery, local.id)).result.status, 'confirmed'); assert.equal(writes.length, 1);
  bridge.load = () => { throw new Error('Original review receipt needs no credentials'); };
  assert.equal((await delivery.review(local.id, target, body, key, user, 'Bearer explicit-company-fixture')).historical, true);
});

test('adoption without a current local entitlement is explicit cleanup only and never performs an automatic removal', async () => {
  const local = await mappedPool(); await manual(local.id); const { delivery } = await unknownAddition(local.id); await manual(local.id, true);
  const review = await delivery.reviewPreview(local.id, target, user, 'Bearer explicit-company-fixture'); assert.equal(review.local.desired, false); await settleReview(review);
  const result = await delivery.review(local.id, target, reviewInput(review, 'adopt'), randomUUID(), user, 'Bearer explicit-company-fixture');
  assert.equal(result.result.status, 'conflict'); assert.equal(result.result.errorCode, 'review_adopted_for_cleanup'); assert.equal(result.result.owned, true); assert.equal(writes.length, 1);
  writeHandler = null; const removal = await sync(delivery, local.id); assert.equal(removal.result.status, 'verifying'); assert.equal(writes.length, 2); assert.equal(writes[1].desired, false);
  assert.equal((await sync(delivery, local.id)).result.owned, false);
});

test('release of an unknown attempt requires current commit authority and a later separately confirmed new dispatch', async () => {
  const local = await mappedPool(); await manual(local.id); const { delivery, before, operation } = await unknownAddition(local.id, false); source.tenant.generation = '2';
  const review = await delivery.reviewPreview(local.id, target, user, 'Bearer explicit-company-fixture'); assert.deepEqual(review.decisions, ['release']); await settleReview(review);
  const key = randomUUID(), body = reviewInput(review, 'release'); source.validUntil = Math.floor(Date.now() / 1000) + 2;
  delayCommit = () => new Promise(resolve => setTimeout(resolve, Math.max(0, source.validUntil * 1000 - Date.now() + 40)));
  await assert.rejects(delivery.review(local.id, target, body, key, user, 'Bearer explicit-company-fixture'), error => error.code === '42501'); delayCommit = null;
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM company_microsoft_operations WHERE id=$1', [key])).rows[0].count, 0);
  source.validUntil = Math.floor(Date.now() / 1000) + 300;
  const app = express(); app.use(express.json()); app.use((req, _res, next) => { req.user = user; next(); });
  const options = Object.fromEntries(['tenantId', 'readFilename', 'writeFilename', 'load', 'createReader', 'createGraph'].map(name => [name, bridge[name]]));
  app.use('/api/licenses/company', require('../companyRoutes').companyLicenseRoutes(companies.allocator, { authority: companies.authority, microsoft: options }));
  const path = '/api/licenses/company/provider/microsoft/pools/' + local.id + '/users/' + target;
  const preview = await request(app).post(path + '/review-preview').set('Authorization', 'Bearer explicit-company-fixture').send({}); assert.equal(preview.status, 200, JSON.stringify(preview.body));
  const released = await request(app).post(path + '/review').set('Authorization', 'Bearer explicit-company-fixture').set('Idempotency-Key', key).send(body); assert.equal(released.status, 200, JSON.stringify(released.body)); assert.equal(released.body.result.owned, false); assert.equal(released.body.result.status, 'conflict'); assert.equal(writes.length, 1);
  assert.equal((await request(app).post(path + '/review').set('Authorization', 'Bearer explicit-company-fixture').set('Idempotency-Key', key).send(body)).body.historical, true);
  await bridge.connect(connectionInput(), randomUUID(), user, 'Bearer explicit-company-fixture', await connectionVersion());
  writeHandler = null; const added = await sync(delivery, local.id); assert.equal(added.result.kind, 'acknowledged'); assert.equal(writes.length, 2); assert.equal(writes[1].desired, true);
  assert.equal((await sync(delivery, local.id, operation, before)).result.kind, 'unknown');
});

test('unrelated, inherited or plan-changed licenses cannot be adopted through an unknown review', async () => {
  const local = await mappedPool(); await manual(local.id); const delivery = new CompanyMicrosoftDelivery(bridge);
  observed = { present: true, direct: true, active: true, plansMatch: true, inherited: false, accountEnabled: true }; await sync(delivery, local.id);
  await assert.rejects(delivery.reviewPreview(local.id, target, user, 'Bearer explicit-company-fixture'), error => error.status === 409); assert.equal(writes.length, 0);
  observed = { present: false, direct: false, active: false, plansMatch: false, inherited: false, accountEnabled: true };
  const unknown = await unknownAddition(local.id, false);
  for (const remote of [{ present: true, direct: false, active: false, plansMatch: false, inherited: true, accountEnabled: true }, { present: true, direct: true, active: true, plansMatch: false, inherited: false, accountEnabled: true }]) {
    observed = remote; const review = await unknown.delivery.reviewPreview(local.id, target, user, 'Bearer explicit-company-fixture'); assert.deepEqual(review.decisions, ['release']);
    await assert.rejects(unknown.delivery.review(local.id, target, reviewInput(review, 'adopt'), randomUUID(), user, 'Bearer explicit-company-fixture'), error => error.status === 412);
  }
  assert.equal(writes.length, 1);
});

test('a changed or unavailable canonical group source cannot authorize an unknown review even with an overlapping manual claim', async () => {
  const local = await mappedPool(); await manual(local.id); await unknownAddition(local.id); const group = await groupPool(local.id); const delivery = new CompanyMicrosoftDelivery(bridge, { groups: group.service });
  const review = await delivery.reviewPreview(local.id, target, user, 'Bearer explicit-company-fixture'); assert.equal(review.local.groups[0].active, true); group.remove();
  await assert.rejects(delivery.review(local.id, target, reviewInput(review, 'adopt'), randomUUID(), user, 'Bearer explicit-company-fixture'), error => error.status === 412);
  group.fail(); await assert.rejects(delivery.review(local.id, target, reviewInput(review, 'release'), randomUUID(), user, 'Bearer explicit-company-fixture'), error => error.status === 503);
  assert.equal(writes.length, 1);
});

for (const phase of ['prepared', 'dispatched']) test(`explicit recovery of a ${phase} crash keeps the original source and never calls Microsoft`, async () => {
  const local = await mappedPool(); await manual(local.id); const delivery = new CompanyMicrosoftDelivery(bridge);
  if (phase === 'dispatched') source.validUntil = Math.floor(Date.now() / 1000) + 3;
  const crash = await interrupted(delivery, local.id, phase);
  const original = (await pool.query('SELECT * FROM company_microsoft_operations WHERE id=$1', [crash.operation])).rows[0];
  if (phase === 'dispatched') {
    await new Promise(resolve => setTimeout(resolve, Math.max(0, original.source.validUntil * 1000 - Date.now() + 40)));
    assert.equal((await pool.query('SELECT company_microsoft_source_valid($1,$2,$3) AS value', [original.source, original.id, original.request.reason])).rows[0].value, false);
  }
  source.tokenId = randomUUID(); source.validUntil = Math.floor(Date.now() / 1000) + 300;
  bridge.load = () => { throw new Error('Recovery must not load the unavailable provider configuration'); };
  calls = []; const review = await delivery.recoveryPreview(local.id, target, user, 'Bearer explicit-company-fixture'); const operation = randomUUID();
  assert.equal(review.attempt.id, crash.operation); assert.equal(review.attempt.phase, phase);
  const request = recoveryInput(review); const result = await delivery.recover(local.id, target, request, operation, user, 'Bearer explicit-company-fixture');
  assert.equal(result.result.kind, phase === 'prepared' ? 'not_sent' : 'unknown'); assert.equal(result.result.status, phase === 'prepared' ? 'failed' : 'unknown');
  assert.equal(result.result.owned, false); assert.equal(result.result.uncertainOperationId, phase === 'dispatched' ? crash.operation : null); assert.equal(result.result.interruptedOperationId, crash.operation);
  assert.equal((await delivery.recover(local.id, target, request, operation, user, 'Bearer explicit-company-fixture')).historical, true);
  const after = (await pool.query('SELECT * FROM company_microsoft_operations WHERE id=$1', [crash.operation])).rows[0];
  assert.deepEqual(after.source, original.source); assert.deepEqual(after.request, original.request); assert.equal(after.permit_hash, original.permit_hash); assert.equal(after.phase, 'finished');
  const actors = (await pool.query('SELECT actor FROM company_microsoft_events WHERE operation_id=$1 ORDER BY sequence', [crash.operation])).rows.map(row => row.actor);
  assert.deepEqual(actors.at(-1), { kind: 'workload', operationId: crash.operation });
  const recovery = (await pool.query('SELECT source FROM company_microsoft_operations WHERE id=$1', [operation])).rows[0]; assert.equal(recovery.source.tokenId, source.tokenId);
  await assert.rejects(pool.query('SELECT company_microsoft_dispatch($1,$2)', [crash.operation, crash.nonce]), error => error.code === '42501');
  assert.equal((await delivery.recoveryPreview(local.id, target, user, 'Bearer explicit-company-fixture')).attempt, null);
  assert.deepEqual(calls, []); assert.equal(writes.length, 0);
});

test('recovery rejects a live target lock and a reviewed phase that has since changed', async () => {
  const local = await mappedPool(); await manual(local.id); const delivery = new CompanyMicrosoftDelivery(bridge); const crash = await interrupted(delivery, local.id, 'prepared');
  const review = await delivery.recoveryPreview(local.id, target, user, 'Bearer explicit-company-fixture'); const held = await pool.connect();
  try {
    await held.query('SELECT pg_advisory_lock(hashtextextended($1,0))', ['company-microsoft:' + crash.targetId]);
    await assert.rejects(delivery.recover(local.id, target, recoveryInput(review), randomUUID(), user, 'Bearer explicit-company-fixture'), error => error.code === '55000');
  } finally { await held.query('SELECT pg_advisory_unlock(hashtextextended($1,0))', ['company-microsoft:' + crash.targetId]); held.release(); }
  const dispatchClient = await pool.connect();
  try { await delivery.transaction(dispatchClient, () => dispatchClient.query('SELECT company_microsoft_dispatch($1,$2)', [crash.operation, crash.nonce])); }
  finally { dispatchClient.release(); }
  await assert.rejects(delivery.recover(local.id, target, recoveryInput(review), randomUUID(), user, 'Bearer explicit-company-fixture'), error => error.status === 412);
  assert.equal(writes.length, 0);
});

test('fresh human recovery authority is checked again at physical commit and rolls back the old workload receipt', async () => {
  const local = await mappedPool(); await manual(local.id); const delivery = new CompanyMicrosoftDelivery(bridge); const crash = await interrupted(delivery, local.id, 'dispatched');
  const review = await delivery.recoveryPreview(local.id, target, user, 'Bearer explicit-company-fixture'); const operation = randomUUID();
  source.validUntil = Math.floor(Date.now() / 1000) + 2;
  delayCommit = () => new Promise(resolve => setTimeout(resolve, Math.max(0, source.validUntil * 1000 - Date.now() + 40)));
  await assert.rejects(delivery.recover(local.id, target, recoveryInput(review), operation, user, 'Bearer explicit-company-fixture'), error => error.code === '42501'); delayCommit = null;
  assert.equal((await pool.query('SELECT phase FROM company_microsoft_operations WHERE id=$1', [crash.operation])).rows[0].phase, 'dispatched');
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM company_microsoft_operations WHERE id=$1', [operation])).rows[0].count, 0); assert.equal(writes.length, 0);
});

test('a different currently authorized administrator is recorded separately from the interrupted human', async () => {
  const local = await mappedPool(); await manual(local.id); const delivery = new CompanyMicrosoftDelivery(bridge); const crash = await interrupted(delivery, local.id, 'prepared');
  const previousActor = source.actorUserId; source.actorUserId = randomUUID(); source.context = { ...source.context, userId: source.actorUserId }; user.identity_authorization = source.context;
  source.subject = user.sub = 'explicit-recovery-administrator'; source.tokenId = user.jti = randomUUID(); user.mfa_authorization.userId = source.actorUserId;
  const review = await delivery.recoveryPreview(local.id, target, user, 'Bearer explicit-company-fixture'); const operation = randomUUID();
  await delivery.recover(local.id, target, recoveryInput(review), operation, user, 'Bearer explicit-company-fixture');
  const old = (await pool.query('SELECT source FROM company_microsoft_operations WHERE id=$1', [crash.operation])).rows[0]; assert.equal(old.source.actorUserId, previousActor);
  assert.deepEqual((await pool.query('SELECT actor FROM company_microsoft_events WHERE operation_id=$1', [operation])).rows.map(row => row.actor), [{ kind: 'human', userId: source.actorUserId }]);
  const originalActors = (await pool.query('SELECT actor FROM company_microsoft_events WHERE operation_id=$1 ORDER BY sequence', [crash.operation])).rows.map(row => row.actor);
  assert.deepEqual(originalActors, [{ kind: 'human', userId: previousActor }, { kind: 'workload', operationId: crash.operation }]); assert.equal(writes.length, 0);
});

test('a fresh recovery permit cannot acknowledge an unknown write or become a dispatch permit', async () => {
  const local = await mappedPool(); await manual(local.id); const delivery = new CompanyMicrosoftDelivery(bridge); const crash = await interrupted(delivery, local.id, 'dispatched');
  for (const attack of ['acknowledge', 'dispatch']) {
    const client = await pool.connect(); const operation = randomUUID(), nonce = randomBytes(32).toString('hex');
    try {
      await client.query('BEGIN');
      await client.query("SELECT set_config('opendirectory.company_microsoft_operation',$1,true),set_config('opendirectory.company_microsoft_permit',$2,true),set_config('opendirectory.company_microsoft_purpose','change',true)", [operation, nonce]);
      await client.query(`INSERT INTO company_microsoft_operations(id,tenant_id,connection_id,resource_id,action,source,request,permit_hash,phase)
        SELECT $1,tenant_id,connection_id,resource_id,'recover',$2,$3,encode(sha256(convert_to($4,'UTF8')),'hex'),'prepared' FROM company_microsoft_operations WHERE id=$5`,
      [operation, crash.source, { ...input(), poolId: local.id, userId: target, interruptedOperationId: crash.operation, interruptedPhase: 'dispatched' }, nonce, crash.operation]);
      await client.query("SELECT set_config('opendirectory.company_microsoft_recovery',$1,true)", [operation]);
      if (attack === 'acknowledge') await assert.rejects(client.query('SELECT company_microsoft_finish($1,$2,$3)', [crash.operation, nonce, { kind: 'acknowledged', errorCode: null, retryAfter: null }]), error => error.code === '42501');
      else await assert.rejects(client.query('SELECT company_microsoft_dispatch($1,$2)', [crash.operation, nonce]), error => error.code === '42501');
    } finally { await client.query('ROLLBACK'); client.release(); }
  }
  assert.equal((await pool.query('SELECT phase FROM company_microsoft_operations WHERE id=$1', [crash.operation])).rows[0].phase, 'dispatched'); assert.equal(writes.length, 0);
});

test('recovery of an interrupted observation retains a prior acknowledged addition until independent confirmation', async () => {
  const local = await mappedPool(); await manual(local.id); const delivery = new CompanyMicrosoftDelivery(bridge); const added = await sync(delivery, local.id);
  const crash = await interrupted(delivery, local.id, 'prepared'); const review = await delivery.recoveryPreview(local.id, target, user, 'Bearer explicit-company-fixture');
  const recovered = await delivery.recover(local.id, target, recoveryInput(review), randomUUID(), user, 'Bearer explicit-company-fixture');
  assert.equal(recovered.result.pendingOperationId, added.result.operationId); assert.equal(recovered.result.owned, true); assert.equal(writes.length, 1);
  const confirmed = await sync(delivery, local.id); assert.equal(confirmed.result.status, 'confirmed'); assert.equal(confirmed.result.pendingOperationId, null); assert.equal(writes.length, 1);
});

test('the mounted recovery API uses the retained pair without credentials and records its actual human and workload history', async () => {
  const local = await mappedPool(); await manual(local.id); const delivery = new CompanyMicrosoftDelivery(bridge); const crash = await interrupted(delivery, local.id, 'dispatched'); calls = [];
  const app = express(); app.use(express.json()); app.use((req, _res, next) => { req.user = user; next(); });
  const options = Object.fromEntries(['tenantId', 'readFilename', 'writeFilename', 'createReader', 'createGraph'].map(key => [key, bridge[key]]));
  options.load = () => { throw new Error('Recovery cannot load provider credentials'); };
  app.use('/api/licenses/company', require('../companyRoutes').companyLicenseRoutes(companies.allocator, { authority: companies.authority, microsoft: options }));
  const base = '/api/licenses/company/provider/microsoft'; const path = base + '/pools/' + local.id + '/users/' + target;
  const review = await request(app).post(path + '/recovery-preview').set('Authorization', 'Bearer explicit-company-fixture').send({}); assert.equal(review.status, 200, JSON.stringify(review.body));
  const operation = randomUUID(), body = recoveryInput(review.body);
  const bad = await request(app).post(path + '/recover').set('Idempotency-Key', operation).send({ ...body, actorUserId: randomUUID() }); assert.equal(bad.status, 400);
  const result = await request(app).post(path + '/recover').set('Idempotency-Key', operation).send(body); assert.equal(result.status, 200, JSON.stringify(result.body)); assert.equal(result.body.result.interruptedOperationId, crash.operation); assert.equal(result.body.result.status, 'unknown');
  assert.equal((await request(app).post(path + '/recover').set('Idempotency-Key', operation).send(body)).body.historical, true);
  const history = await request(app).get(base + '/history?page=1'); assert.equal(history.status, 200); assert.ok(history.body.events.some(event => event.type === 'recover' && event.actorUserId === source.actorUserId));
  assert.ok(history.body.events.some(event => event.type === 'sync_finished' && event.actorKind === 'workload' && event.operationId === crash.operation && event.actorUserId === null)); assert.deepEqual(calls, []); assert.equal(writes.length, 0);
});

test('a company Microsoft add and remove each dispatch once and only independent reads confirm the effect', async () => {
  const local = await mappedPool(); await manual(local.id); const delivery = new CompanyMicrosoftDelivery(bridge); const addId = randomUUID();
  const before = await delivery.preview(local.id, target, user, 'Bearer explicit-company-fixture');
  const added = await sync(delivery, local.id, addId, before); assert.equal(added.result.status, 'verifying'); assert.equal(added.result.pendingOperationId, addId); assert.equal(added.result.owned, true); assert.equal(writes.length, 1);
  const repeated = await sync(delivery, local.id, addId, before); assert.equal(repeated.historical, true); assert.equal(repeated.result.status, 'verifying'); assert.equal(writes.length, 1);
  const confirmed = await sync(delivery, local.id); assert.equal(confirmed.result.status, 'confirmed'); assert.equal(confirmed.result.pendingOperationId, null); assert.equal(writes.length, 1);
  await manual(local.id, true); const removalId = randomUUID(); const removal = await sync(delivery, local.id, removalId);
  assert.equal(removal.result.status, 'verifying'); assert.equal(removal.result.pendingOperationId, removalId); assert.equal(removal.result.owned, true); assert.equal(writes.length, 2); assert.equal(writes[1].desired, false);
  const absent = await sync(delivery, local.id); assert.equal(absent.result.status, 'confirmed'); assert.equal(absent.result.owned, false); assert.equal(absent.result.pendingOperationId, null); assert.equal(writes.length, 2);
  await assert.rejects(pool.query('SELECT company_microsoft_dispatch($1,$2)', [addId, permits[0]]), error => error.code === '42501');
  const records = JSON.stringify((await pool.query('SELECT source,request,before_state,outcome,permit_hash FROM company_microsoft_operations')).rows);
  assert.equal(records.includes('fixture-ms-access-token'), false); for (const nonce of permits) assert.equal(records.includes(nonce), false);
});

test('a lost Microsoft response remains durably unknown and is never resent or automatically adopted', async () => {
  const { ProviderError } = require('../fulfillment/transport'); const local = await mappedPool(); await manual(local.id); const delivery = new CompanyMicrosoftDelivery(bridge); const operation = randomUUID();
  writeHandler = async desired => { observed = { present: desired, direct: desired, active: desired, plansMatch: desired, inherited: false, accountEnabled: true }; throw new ProviderError('graph_write_unavailable', { uncertain: true }); };
  const before = await delivery.preview(local.id, target, user, 'Bearer explicit-company-fixture'); const receipt = await sync(delivery, local.id, operation, before);
  assert.equal(receipt.result.status, 'unknown'); assert.equal(receipt.result.owned, false); assert.equal(receipt.result.uncertainOperationId, operation); assert.equal(writes.length, 1);
  assert.equal((await sync(delivery, local.id, operation, before)).historical, true); assert.equal(writes.length, 1);
  const inspected = await sync(delivery, local.id); assert.equal(inspected.result.status, 'unknown'); assert.equal(inspected.result.owned, false); assert.equal(inspected.result.uncertainOperationId, operation); assert.equal(writes.length, 1);
});

test('a changed reviewed action, local recipient or configuration never admits a new cloud write', async () => {
  const local = await mappedPool(); await manual(local.id); const delivery = new CompanyMicrosoftDelivery(bridge);
  const before = await delivery.preview(local.id, target, user, 'Bearer explicit-company-fixture');
  await assert.rejects(delivery.sync(local.id, target, { ...input(), fingerprint: before.fingerprint, action: 'remove' }, randomUUID(), user, 'Bearer explicit-company-fixture'), error => error.status === 412);
  targetState.enabled = false;
  await assert.rejects(sync(delivery, local.id, randomUUID(), before), error => error.status === 412);
  targetState.enabled = true;
  const load = bridge.load; bridge.load = name => ({ ...load(name), clientId: randomUUID() });
  await assert.rejects(sync(delivery, local.id, randomUUID(), before), error => error.status === 409);
  assert.equal(writes.length, 0);
  assert.equal((await pool.query("SELECT count(*)::int AS count FROM company_microsoft_operations WHERE action='sync'")).rows[0].count, 0);
});

test('canonical group removal after durable prepare prevents dispatch and retains a not-sent receipt', async () => {
  const local = await mappedPool(); const group = await groupPool(local.id); const delivery = new CompanyMicrosoftDelivery(bridge, { groups: group.service });
  const before = await delivery.preview(local.id, target, user, 'Bearer explicit-company-fixture'); const operation = randomUUID();
  delayCommit = async () => { group.remove(); delayCommit = null; };
  await assert.rejects(sync(delivery, local.id, operation, before), error => error.status === 412);
  assert.equal(writes.length, 0);
  const saved = (await pool.query('SELECT phase,outcome FROM company_microsoft_operations WHERE id=$1', [operation])).rows[0];
  assert.equal(saved.phase, 'finished'); assert.equal(saved.outcome.kind, 'not_sent'); assert.equal(saved.outcome.errorCode, 'dispatch_precheck_failed');
});

test('prepare and dispatch physical commits independently reject an expired human source before any Graph write', async () => {
  const local = await mappedPool(); await manual(local.id); const delivery = new CompanyMicrosoftDelivery(bridge);
  for (const stage of [1, 2]) {
    source.validUntil = Math.floor(Date.now() / 1000) + 300; const before = await delivery.preview(local.id, target, user, 'Bearer explicit-company-fixture');
    source.validUntil = Math.floor(Date.now() / 1000) + 2; let commits = 0; const operation = randomUUID();
    delayCommit = async () => { if (++commits === stage) await new Promise(resolve => setTimeout(resolve, Math.max(0, source.validUntil * 1000 - Date.now() + 40))); };
    await assert.rejects(sync(delivery, local.id, operation, before), error => error.code === '42501' || [401, 428].includes(error.status)); delayCommit = null; assert.equal(writes.length, 0);
    const result = (await pool.query('SELECT phase,outcome FROM company_microsoft_operations WHERE id=$1', [operation])).rows[0];
    if (stage === 1) assert.equal(result, undefined); else { assert.equal(result.phase, 'finished'); assert.equal(result.outcome.kind, 'not_sent'); }
  }
});

test('an acknowledgement after authority expires still records the original workload result without returning private success', async () => {
  const local = await mappedPool(); await manual(local.id); const delivery = new CompanyMicrosoftDelivery(bridge);
  const before = await delivery.preview(local.id, target, user, 'Bearer explicit-company-fixture'); source.validUntil = Math.floor(Date.now() / 1000) + 2; const operation = randomUUID();
  writeHandler = async desired => { await new Promise(resolve => setTimeout(resolve, Math.max(0, source.validUntil * 1000 - Date.now() + 40))); observed = { present: desired, direct: desired, active: desired, plansMatch: desired, inherited: false, accountEnabled: true }; };
  await assert.rejects(sync(delivery, local.id, operation, before), error => [401, 428].includes(error.status)); assert.equal(writes.length, 1);
  const saved = (await pool.query('SELECT phase,outcome,source FROM company_microsoft_operations WHERE id=$1', [operation])).rows[0]; assert.equal(saved.phase, 'finished'); assert.equal(saved.outcome.kind, 'acknowledged'); assert.equal(saved.outcome.status, 'verifying');
  const actors = (await pool.query('SELECT actor FROM company_microsoft_events WHERE operation_id=$1 ORDER BY sequence', [operation])).rows.map(row => row.actor);
  assert.deepEqual(actors, [{ kind: 'human', userId: source.actorUserId }, { kind: 'workload', operationId: operation }, { kind: 'workload', operationId: operation }]);
});

test('pending writes survive read-only observations and desired-state reversal without a second dispatch', async () => {
  const local = await mappedPool(); await manual(local.id); const delivery = new CompanyMicrosoftDelivery(bridge); writeHandler = async () => {};
  const added = await sync(delivery, local.id); const pending = added.result.pendingOperationId;
  const waiting = await sync(delivery, local.id); assert.equal(waiting.result.pendingOperationId, pending); assert.equal(waiting.result.status, 'verifying'); assert.equal(writes.length, 1);
  await manual(local.id, true); const stillWaiting = await sync(delivery, local.id); assert.equal(stillWaiting.result.pendingOperationId, pending); assert.equal(writes.length, 1);
  observed = { present: true, direct: true, active: true, plansMatch: true, inherited: false, accountEnabled: true };
  const changed = await sync(delivery, local.id); assert.equal(changed.result.pendingOperationId, null); assert.equal(changed.result.errorCode, 'desired_changed'); assert.equal(changed.result.owned, true); assert.equal(writes.length, 1);
  const removal = await sync(delivery, local.id); assert.equal(removal.result.status, 'verifying'); assert.equal(writes.length, 2);
  observed = { present: true, direct: false, active: false, plansMatch: false, inherited: true, accountEnabled: true };
  const retained = await sync(delivery, local.id); assert.equal(retained.result.pendingOperationId, null); assert.equal(retained.result.owned, false); assert.equal(retained.result.errorCode, 'external_assignment_retained'); assert.equal(writes.length, 2);
});

test('a definite Microsoft throttle persists its wait and historical receipts remain readable without credentials', async () => {
  const { ProviderError } = require('../fulfillment/transport'); const local = await mappedPool(); await manual(local.id); const delivery = new CompanyMicrosoftDelivery(bridge); const operation = randomUUID();
  writeHandler = async () => { throw new ProviderError('graph_write_http_429', { uncertain: false, retryAfter: 60 }); };
  const before = await delivery.preview(local.id, target, user, 'Bearer explicit-company-fixture'); const rejected = await sync(delivery, local.id, operation, before);
  assert.equal(rejected.result.kind, 'rejected'); assert.equal(rejected.result.status, 'failed'); assert.equal(rejected.result.owned, false); assert.ok(Date.parse(rejected.result.retryAt) > Date.now());
  const current = await delivery.preview(local.id, target, user, 'Bearer explicit-company-fixture'); await assert.rejects(sync(delivery, local.id, randomUUID(), current), error => error.status === 429); assert.equal(writes.length, 1);
  bridge.load = () => { throw new Error('explicit unavailable file fixture'); };
  assert.equal((await bridge.state(user, 'Bearer explicit-company-fixture')).state, 'configuration_unavailable');
  const historical = await sync(delivery, local.id, operation, before); assert.equal(historical.historical, true); assert.equal(historical.result.kind, 'rejected'); assert.equal(writes.length, 1);
});

test('an ambiguous transport error cannot become certain merely because a supplied uncertainty flag is false', async () => {
  const { ProviderError } = require('../fulfillment/transport'); const local = await mappedPool(); await manual(local.id); const delivery = new CompanyMicrosoftDelivery(bridge);
  writeHandler = async () => { throw new ProviderError('graph_write_http_500', { uncertain: false }); };
  const value = await sync(delivery, local.id); assert.equal(value.result.kind, 'unknown'); assert.equal(value.result.owned, false); assert.equal(writes.length, 1);
});

test('the target session lock prevents concurrent requests from dispatching the same reviewed license twice', { timeout: 15000 }, async () => {
  const local = await mappedPool(); await manual(local.id); const delivery = new CompanyMicrosoftDelivery(bridge); const before = await delivery.preview(local.id, target, user, 'Bearer explicit-company-fixture');
  let release, entered; const inWrite = new Promise(resolve => { entered = resolve; }); const hold = new Promise(resolve => { release = resolve; });
  writeHandler = async desired => { entered(); await hold; observed = { present: desired, direct: desired, active: desired, plansMatch: desired, inherited: false, accountEnabled: true }; };
  const first = sync(delivery, local.id, randomUUID(), before); await Promise.race([inWrite, first.then(() => { throw new Error('First request ended without reaching the provider'); })]);
  let timer;
  try { await assert.rejects(Promise.race([sync(delivery, local.id, randomUUID(), before), new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('Concurrent request did not reject within5seconds')), 5000); })]), error => error.status === 409); assert.equal(writes.length, 1); }
  finally { clearTimeout(timer); release(); }
  assert.equal((await first).result.status, 'verifying'); assert.equal(writes.length, 1);
});

test('a held target client does not request a second pool connection to check the original operation', async () => {
  const local = await mappedPool(); await manual(local.id);
  const single = new Pool({ connectionString: process.env.LICENSE_TEST_DATABASE_URL, options: '-c search_path=' + schema + ',public', max: 1, connectionTimeoutMillis: 1000 });
  bridge.database = { query: (...args) => single.query(...args), getClient: () => single.connect() };
  try {
    const result = await sync(new CompanyMicrosoftDelivery(bridge), local.id);
    assert.equal(result.result.kind, 'acknowledged'); assert.equal(writes.length, 1);
  } finally { await single.end(); }
});

test('a provider assignment failure is retained with its pending original attempt and cannot claim confirmation', async () => {
  const { ProviderError } = require('../fulfillment/transport'); const local = await mappedPool(); await manual(local.id); const delivery = new CompanyMicrosoftDelivery(bridge); await sync(delivery, local.id);
  const previous = bridge.createGraph;
  bridge.createGraph = config => ({ ...previous(config), inspect: async () => { const error = new ProviderError('graph_assignment_error'); error.observation = { present: true, direct: true, active: false, plansMatch: true, inherited: false, accountEnabled: true }; throw error; } });
  const failed = await sync(delivery, local.id); assert.equal(failed.result.status, 'failed'); assert.equal(failed.result.errorCode, 'graph_assignment_error'); assert.ok(failed.result.pendingOperationId); assert.equal(writes.length, 1);
});
test('missing provider files do not prevent the authorized owner from retiring unused metadata', async () => {
  const local = await mappedPool(); const mappings = await bridge.mappings(local.id, { page: '1' }, user, 'Bearer explicit-company-fixture'); bridge.load = () => { throw new Error('fixture file removed'); };
  assert.equal((await bridge.state(user, 'Bearer explicit-company-fixture')).state, 'configuration_unavailable');
  assert.equal((await bridge.retire('pool', mappings.pool.id, '1', randomUUID(), input(), user, 'Bearer explicit-company-fixture')).binding.status, 'retired');
  assert.equal((await bridge.retire('user', mappings.users[0].id, '1', randomUUID(), input(), user, 'Bearer explicit-company-fixture')).binding.status, 'retired');
  assert.equal(writes.length, 0); assert.equal((await bridge.history({ page: '1' }, user, 'Bearer explicit-company-fixture')).events.length, 5);
});
async function groupPool(poolId) {
  const { CompanyBlueprints } = require('../../CompanyBlueprints'); const { CompanyBlueprintAssignments } = require('../CompanyBlueprintAssignments');
  const { CompanyLicenseGroups } = require('../CompanyLicenseGroups'); const { normalizeSnapshot } = require('../GroupSnapshotClient');
  const groupId = randomUUID(); const members = new Set([target]); let reads = 0, changeAt = Infinity, unavailable = false;
  const groups = { snapshot: async (id, auth, company) => {
    assert.equal(id, groupId); assert.equal(auth, 'Bearer explicit-company-fixture'); assert.equal(company, true); reads++;
    if (unavailable) throw Object.assign(new Error('Explicit group fixture unavailable'), { status: 503 });
    if (reads >= changeAt) members.clear(); const observedAt = new Date();
    return normalizeSnapshot({ schemaVersion: 3, groupId, name: 'Current Microsoft licensing group', revision: members.size ? '1' : '2', deleted: false,
      memberIds: [...members], inactiveMemberIds: [], unresolvedMemberIds: [], viewerUserId: source.actorUserId, viewerEnabled: true, sourceAuthorization: null,
      observedAt: observedAt.toISOString(), validUntil: new Date(observedAt.getTime() + 300000).toISOString(),
      memberships: [...members].map(userId => ({ userId, membershipId: userId, eligibilityRevision: targetState.eligibilityRevision, reviewDeadlineAt: null })) }, groupId);
  } };
  const applicationAuthority = companies.authority, authority = companies.sourceOptions.assignmentAuthority;
  const blueprintAuthority = { read: async () => { const { target: unused, ...base } = await applicationAuthority.read(); return { ...base, companyBlueprintProtocol: 1, permissions: ['company.blueprints.read', 'company.blueprints.manage', 'company.blueprints.publish'] }; } };
  const service = new CompanyLicenseGroups(companies, { groups, blueprints: new CompanyBlueprints(database, { authority: blueprintAuthority, applicationAuthority }),
    assignments: new CompanyBlueprintAssignments(database, { allocator: companies.allocator, authority, applicationAuthority }) });
  const linked = await service.link({ groupId, poolId, ...input() }, randomUUID(), user, 'Bearer explicit-company-fixture');
  const result = await service.sync(linked.rule.id, { groupRevision: '1', cursor: null, ...input() }, user, 'Bearer explicit-company-fixture'); assert.equal(result.results[0].status, 'assigned');
  return { service, remove: () => members.clear(), fail: () => { unavailable = true; }, changeDuringPreview: () => { changeAt = reads + 2; } };
}

test('Microsoft preview derives a real local manual grant and makes no write or ownership claim', async () => {
  const local = await mappedPool(); await manual(local.id); const delivery = new CompanyMicrosoftDelivery(bridge);
  const preview = await delivery.preview(local.id, target, user, 'Bearer explicit-company-fixture');
  assert.equal(preview.action, 'assign'); assert.equal(preview.local.desired, true); assert.equal(preview.local.raw.origins.length, 1); assert.equal(preview.local.raw.origins[0].sourceType, 'direct');
  assert.equal(preview.target, null); assert.match(preview.fingerprint, /^[a-f0-9]{64}$/); assert.equal((await pool.query('SELECT count(*)::int AS count FROM company_microsoft_targets')).rows[0].count, 0);
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM company_microsoft_operations')).rows[0].count, 3);
});

test('disabled or re-enabled generations cannot revive an older stored local seat for Microsoft', async () => {
  const local = await mappedPool(); await manual(local.id); const delivery = new CompanyMicrosoftDelivery(bridge);
  targetState.eligibilityRevision = '2'; targetState.enabled = false;
  assert.equal((await delivery.preview(local.id, target, user, 'Bearer explicit-company-fixture')).local.desired, false);
  targetState.enabled = true;
  assert.equal((await delivery.preview(local.id, target, user, 'Bearer explicit-company-fixture')).local.desired, false);
  assert.equal((await pool.query('SELECT used_seats FROM license_catalog WHERE id=$1', [local.id])).rows[0].used_seats, 1);
});

test('pre-existing direct or group Microsoft licenses remain external even when a local seat is wanted', async () => {
  const local = await mappedPool(); await manual(local.id); const delivery = new CompanyMicrosoftDelivery(bridge);
  for (const value of [{ present: true, direct: true, active: true, plansMatch: true, inherited: false, accountEnabled: true }, { present: true, direct: false, active: false, plansMatch: false, inherited: true, accountEnabled: true }]) {
    observed = value; const preview = await delivery.preview(local.id, target, user, 'Bearer explicit-company-fixture'); assert.equal(preview.action, 'conflict'); assert.equal(preview.target, null);
  }
});
test('a current exhausted or absent Microsoft SKU cannot become a proposed new cloud assignment', async () => {
  const local = await mappedPool(); await manual(local.id); const delivery = new CompanyMicrosoftDelivery(bridge); sku.consumedUnits = sku.prepaidUnits.enabled;
  const full = await delivery.preview(local.id, target, user, 'Bearer explicit-company-fixture'); assert.equal(full.local.desired, true); assert.equal(full.action, 'conflict'); assert.equal(full.stock.consumedUnits, 10);
  bridge.createReader = () => ({ inspect: async () => [] }); const absent = await delivery.preview(local.id, target, user, 'Bearer explicit-company-fixture'); assert.equal(absent.action, 'conflict'); assert.equal(absent.stock, null);
});

test('Microsoft entitlement ignores a stale materialized group seat while retaining an overlapping actual manual grant', async () => {
  const local = await mappedPool(); const group = await groupPool(local.id); const delivery = new CompanyMicrosoftDelivery(bridge, { groups: group.service });
  const first = await delivery.preview(local.id, target, user, 'Bearer explicit-company-fixture'); assert.equal(first.local.desired, true); assert.equal(first.local.groups[0].active, true);
  await manual(local.id); group.remove();
  const overlap = await delivery.preview(local.id, target, user, 'Bearer explicit-company-fixture'); assert.equal(overlap.local.desired, true); assert.equal(overlap.local.groups[0].active, false); assert.equal(overlap.local.raw.origins.length, 2);
  await manual(local.id, true); const stale = await delivery.preview(local.id, target, user, 'Bearer explicit-company-fixture');
  assert.equal(stale.local.desired, false); assert.equal(stale.local.raw.origins.length, 1); assert.notEqual(stale.fingerprint, overlap.fingerprint);
  assert.equal((await pool.query('SELECT used_seats FROM license_catalog WHERE id=$1', [local.id])).rows[0].used_seats, 1);
});

test('an unavailable or changing canonical group source cannot become a Microsoft entitlement decision', async () => {
  const local = await mappedPool(); const group = await groupPool(local.id); const delivery = new CompanyMicrosoftDelivery(bridge, { groups: group.service });
  group.changeDuringPreview(); await assert.rejects(delivery.preview(local.id, target, user, 'Bearer explicit-company-fixture'), error => error.status === 412);
  group.fail(); calls = []; await assert.rejects(delivery.preview(local.id, target, user, 'Bearer explicit-company-fixture'), error => error.status === 503); assert.equal(calls.includes('inspect'), false);
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM company_microsoft_targets')).rows[0].count, 0);
});

test('company Microsoft metadata binds the operator-selected tenant, own pool and reviewed user with retained audit', async () => {
  const local = await createPool(); const key = randomUUID();
  const connected = await bridge.connect(connectionInput(), key, user, 'Bearer explicit-company-fixture');
  assert.equal((await bridge.connect(connectionInput(), key, user, 'Bearer explicit-company-fixture')).historical, true);
  const product = await bridge.bindPool(local.id, { ...input(), skuId: sku.skuId, exclusiveDirectManagement: true }, await connectionVersion(), randomUUID(), user, 'Bearer explicit-company-fixture');
  const person = await bridge.bindUser(target, { ...input(), objectId: remoteId, exclusiveDirectManagement: true }, await connectionVersion(), randomUUID(), user, 'Bearer explicit-company-fixture');
  assert.equal(product.pool.poolId, local.id); assert.equal(person.user.objectId, remoteId);
  const current = await bridge.state(user, 'Bearer explicit-company-fixture'); assert.equal(current.state, 'connected'); assert.equal(current.connection.id, connected.connection.id);
  const mappings = await bridge.mappings(local.id, { page: '1' }, user, 'Bearer explicit-company-fixture'); assert.equal(mappings.users.length, 1); assert.equal(mappings.pool.skuId, sku.skuId);
  const history = await bridge.history({ page: '1' }, user, 'Bearer explicit-company-fixture'); assert.equal(history.events.length, 3); assert.ok(history.events.every(value => value.actorUserId === source.actorUserId));
  const records = JSON.stringify((await pool.query('SELECT source,request,outcome FROM company_microsoft_operations')).rows);
  assert.equal(records.includes('explicit-fixture-secret'), false); assert.equal(records.includes('Bearer explicit-company-fixture'), false);
});

test('foreign targets, unsupported selectors and stale connection revisions make no provider request', async () => {
  const local = await createPool(); await connect(); calls = [];
  await assert.rejects(bridge.connect({ ...connectionInput(), tenantId: randomUUID() }, randomUUID(), user, 'Bearer explicit-company-fixture'));
  await assert.rejects(bridge.bindUser(randomUUID(), { ...input(), objectId: remoteId, exclusiveDirectManagement: true }, await connectionVersion(), randomUUID(), user, 'Bearer explicit-company-fixture'), error => error.status === 404);
  await assert.rejects(bridge.bindPool(local.id, { ...input(), skuId: sku.skuId, exclusiveDirectManagement: true }, await connectionVersion('9'), randomUUID(), user, 'Bearer explicit-company-fixture'), error => error.status === 412);
  await assert.rejects(bridge.bindPool(local.id, { ...input(), skuId: sku.skuId, exclusiveDirectManagement: true }, { id: randomUUID(), revision: '1' }, randomUUID(), user, 'Bearer explicit-company-fixture'), error => error.status === 412);
  assert.deepEqual(calls, []);
});

test('reapplying the metadata migration preserves receipts and denies a legacy worker every company Microsoft function', async () => {
  const connected = await connect();
  await pool.query(fs.readFileSync(path.join(__dirname, '../../db/migrations/031_company_microsoft.sql'), 'utf8'));
  await pool.query(fs.readFileSync(path.join(__dirname, '../../db/migrations/032_company_microsoft_delivery.sql'), 'utf8'));
  assert.equal((await bridge.state(user, 'Bearer explicit-company-fixture')).connection.id, connected.connection.id);
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM company_microsoft_events')).rows[0].count, 1);
  const role = 'microsoft_legacy_' + randomUUID().replaceAll('-', ''); let limited;
  await admin.query(`CREATE ROLE ${role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOINHERIT`);
  try {
    const grants = fs.readFileSync(path.join(__dirname, '../../../scripts/license-fulfillment-grants.sql'), 'utf8').replaceAll(':"license_schema"', `"${schema}"`).replaceAll(':"worker_role"', `"${role}"`); await pool.query(grants);
    const url = new URL(process.env.LICENSE_TEST_DATABASE_URL); url.username = role; url.password = '';
    limited = new Pool({ connectionString: url.toString(), max: 1, options: '-c search_path=' + schema + ',public' });
    const signatures = (await pool.query('SELECT signature FROM company_microsoft_receiver_manifest UNION ALL SELECT signature FROM company_microsoft_delivery_manifest')).rows;
    for (const row of signatures) assert.equal((await limited.query("SELECT has_function_privilege(current_user,to_regprocedure($1),'EXECUTE') AS allowed", [row.signature])).rows[0].allowed, false, row.signature);
    await assert.rejects(limited.query('SELECT * FROM company_microsoft_connections'), error => error.code === '42501');
    await assert.rejects(limited.query('SELECT company_microsoft_receiving()'), error => error.code === '42501');
  } finally {
    if (limited) await limited.end(); await pool.query(`DROP OWNED BY ${role}`); await admin.query(`DROP ROLE ${role}`);
  }
});

test('Microsoft configuration cannot be rewritten directly and its audit cannot be erased', async () => {
  const connected = await connect();
  await assert.rejects(pool.query('UPDATE company_microsoft_connections SET read_client_id=$2 WHERE id=$1', [connected.connection.id, randomUUID()]), error => error.code === '42501');
  await assert.rejects(pool.query('DELETE FROM company_microsoft_events'), error => error.code === '42501');
  await assert.rejects(pool.query('TRUNCATE company_microsoft_events CASCADE'), error => error.code === '42501');
  await pool.query('ALTER TABLE company_microsoft_events DISABLE TRIGGER company_microsoft_guard');
  await assert.rejects(bridge.state(user, 'Bearer explicit-company-fixture'), error => error.code === '42501');
  await pool.query('ALTER TABLE company_microsoft_events ENABLE TRIGGER company_microsoft_guard');
  assert.equal((await bridge.state(user, 'Bearer explicit-company-fixture')).state, 'connected');
});

test('mapping retirement precedes disconnection and keeps the original receipts', async () => {
  const local = await createPool(), connection = (await connect()).connection;
  const product = (await bridge.bindPool(local.id, { ...input(), skuId: sku.skuId, exclusiveDirectManagement: true }, await connectionVersion(), randomUUID(), user, 'Bearer explicit-company-fixture')).pool;
  await assert.rejects(bridge.retire('connection', connection.id, '1', randomUUID(), input(), user, 'Bearer explicit-company-fixture'), error => error.code === '23514');
  assert.equal((await bridge.retire('pool', product.id, '1', randomUUID(), input(), user, 'Bearer explicit-company-fixture')).binding.status, 'retired');
  assert.equal((await bridge.retire('connection', connection.id, '1', randomUUID(), input(), user, 'Bearer explicit-company-fixture')).binding.status, 'disconnected');
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM company_microsoft_operations')).rows[0].count, 4);
});

test('the mounted company HTTP API persists only the reviewed Microsoft configuration and rejects changed public IDs', async () => {
  const app = express(); app.use(express.json()); app.use((req, _res, next) => { req.user = user; next(); });
  const options = Object.fromEntries(['tenantId', 'readFilename', 'writeFilename', 'load', 'createReader', 'createGraph'].map(key => [key, bridge[key]]));
  app.use('/api/licenses/company', require('../companyRoutes').companyLicenseRoutes(companies.allocator, { authority: companies.authority, microsoft: options }));
  const base = '/api/licenses/company/provider/microsoft'; const local = await createPool();
  const before = await request(app).get(base + '/state').set('Authorization', 'Bearer explicit-company-fixture'); assert.equal(before.status, 200); assert.equal(before.body.state, 'configured');
  const wrong = await request(app).post(base + '/connections').set('Idempotency-Key', randomUUID()).send({ ...connectionInput(), microsoftTenantId: randomUUID() }); assert.equal(wrong.status, 412); assert.deepEqual(calls, []);
  const connected = await request(app).post(base + '/connections').set('Idempotency-Key', randomUUID()).send(connectionInput()); assert.equal(connected.status, 201); assert.equal(connected.headers['cache-control'], 'no-store');
  const bound = await request(app).post(base + '/pools/' + local.id + '/bind').set('If-Match', connected.headers.etag).set('Idempotency-Key', randomUUID()).send({ ...input(), skuId: sku.skuId, exclusiveDirectManagement: true });
  assert.equal(bound.status, 201); assert.equal(bound.body.pool.poolId, local.id);
  const rows = await request(app).get(base + '/pools/' + local.id + '/mappings?page=1'); assert.equal(rows.status, 200); assert.equal(rows.body.pool.id, bound.body.pool.id);
  const linked = await request(app).post(base + '/users/' + target + '/bind').set('If-Match', connected.headers.etag).set('Idempotency-Key', randomUUID()).send({ ...input(), objectId: remoteId, exclusiveDirectManagement: true }); assert.equal(linked.status, 201);
  const preview = await request(app).post(base + '/pools/' + local.id + '/users/' + target + '/preview').send({}); assert.equal(preview.status, 200, JSON.stringify(preview.body)); assert.equal(preview.body.local.desired, false); assert.equal(preview.body.action, 'confirmed');
  const synced = await request(app).post(base + '/pools/' + local.id + '/users/' + target + '/sync').set('Idempotency-Key', randomUUID()).send({ ...input(), fingerprint: preview.body.fingerprint, action: preview.body.action });
  assert.equal(synced.status, 200, JSON.stringify(synced.body)); assert.equal(synced.body.result.kind, 'observed'); assert.equal(synced.body.result.status, 'confirmed'); assert.equal(writes.length, 0);
  const history = await request(app).get(base + '/history?page=1'); assert.equal(history.status, 200); assert.equal(history.body.events.length, 5);
  assert.equal(history.body.events.filter(event => event.actorKind === 'workload' && event.actorUserId === null).length, 1);
});

test('receiving rejects a correctly named commit trigger that omits updates', async () => {
  await pool.query('DROP TRIGGER company_microsoft_commit_guard ON company_microsoft_operations');
  await pool.query('CREATE CONSTRAINT TRIGGER company_microsoft_commit_guard AFTER INSERT ON company_microsoft_operations DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION company_microsoft_commit_guard()');
  await assert.rejects(bridge.state(user, 'Bearer explicit-company-fixture'), error => error.code === '42501');
});

test('MFA source expiry before the physical SQL commit rolls back configuration and every receipt', async () => {
  source.validUntil = Math.floor(Date.now() / 1000) + 2;
  delayCommit = () => new Promise(resolve => setTimeout(resolve, Math.max(0, source.validUntil * 1000 - Date.now() + 40)));
  await assert.rejects(connect(), error => error.code === '42501' && error.message.includes('expired before commit'));
  for (const table of ['company_microsoft_connections', 'company_microsoft_operations', 'company_microsoft_events', 'company_microsoft_outbox']) {
    assert.equal((await pool.query('SELECT count(*)::int AS count FROM ' + table)).rows[0].count, 0);
  }
});
