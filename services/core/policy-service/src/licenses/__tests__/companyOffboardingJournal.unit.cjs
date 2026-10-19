'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { CompanyOffboardingJournal } = require('../CompanyOffboardingJournal');
const { COMPANY_LICENSE_PERMISSIONS } = require('../../../../../../packages/company-license-contract');

function fixture() {
  const actorUserId = randomUUID(); const userId = randomUUID(); const tenantId = randomUUID(); const workflowId = randomUUID();
  const source = { schemaVersion: 1, issuer: 'https://journal.unit.fixture', subject: 'explicit-owner', tokenId: randomUUID(), expiresAt: Math.floor(Date.now() / 1000) + 3600,
    context: { userId: actorUserId, revision: '1', linkRevision: '1', rolesRevision: 'a'.repeat(64) }, tenant: { id: tenantId, version: '1', generation: '1' },
    actorUserId, permissions: [...COMPANY_LICENSE_PERMISSIONS], validUntil: Math.floor(Date.now() / 1000) + 300,
    target: { id: userId, revision: '1', eligibilityRevision: '1', enabled: true, deleted: false } };
  const intent = { workflowId, userId, userRevision: '1', eligibilityRevision: '1', reason: 'Confirmed company departure review', confirm: true };
  const queries = []; const releases = []; let acquired = true; let unlockError; let rollbackError;
  const client = { async query(sql, parameters) {
    queries.push({ sql, parameters });
    if (sql.includes('pg_try_advisory_lock')) return { rows: [{ acquired }] };
    if (sql.includes('pg_advisory_unlock')) { if (unlockError) throw unlockError; return { rows: [{ unlocked: true }] }; }
    if (sql === 'ROLLBACK' && rollbackError) throw rollbackError;
    if (sql.includes('company_offboarding_create')) return { rows: [{ result: { job: { id: workflowId }, created: true } }] };
    return { rows: [] };
  }, release(error) { releases.push(error); } };
  const database = { getClient: async () => client, query: (...args) => client.query(...args) };
  return { source, intent, queries, releases, client, database, journal: new CompanyOffboardingJournal(database),
    busy() { acquired = false; }, failUnlock(error) { unlockError = error; }, failRollback(error) { rollbackError = error; } };
}

test('session locks use a dedicated connection and tenant plus workflow namespace, without opening a transaction', async () => {
  const state = fixture(); const locked = await state.journal.lock(state.source.tenant.id, state.intent.workflowId);
  assert.equal(locked.client, state.client);
  assert.deepEqual(state.queries.at(-1).parameters, [state.source.tenant.id, state.intent.workflowId]);
  assert.match(state.queries.at(-1).sql, /pg_try_advisory_lock/u); assert.ok(!state.queries.some(query => query.sql === 'BEGIN'));
  await locked.release(); await locked.release(); assert.deepEqual(state.releases, [undefined]);
});

test('busy workflows return 409 and return the connection immediately', async () => {
  const state = fixture(); state.busy();
  await assert.rejects(state.journal.lock(state.source.tenant.id, state.intent.workflowId), error => error.status === 409);
  assert.deepEqual(state.releases, [undefined]);
});

test('unlock errors destroy the pooled connection and cannot leak a session lock', async () => {
  const state = fixture(); const locked = await state.journal.lock(state.source.tenant.id, state.intent.workflowId); const failure = new Error('transport closed'); state.failUnlock(failure);
  await assert.rejects(locked.release(), error => error === failure && error.status === 503);
  assert.deepEqual(state.releases, [failure]); await locked.release(); assert.equal(state.releases.length, 1);
});

test('short independent writes verify the exact connection before and after DML, before commit', async () => {
  const state = fixture();
  const result = await state.journal.create(state.database, state.source, state.intent, async client => { assert.equal(client, state.client); state.queries.push({ sql: 'verified' }); });
  assert.equal(result.created, true);
  const statements = state.queries.map(query => query.sql);
  const mutation = statements.findIndex(sql => sql.includes('company_offboarding_create'));
  assert.ok(statements.indexOf('verified') < mutation); assert.ok(statements.lastIndexOf('verified') > mutation);
  assert.ok(statements.lastIndexOf('verified') < statements.indexOf('COMMIT')); assert.equal(statements[0], 'BEGIN');
  assert.ok(statements.some(sql => sql.includes('statement_timeout'))); assert.deepEqual(state.releases, [undefined]);
});

test('failed after-DML verification rolls back, with destruction on rollback transport failure', async () => {
  const state = fixture(); let checks = 0; const rollbackError = new Error('connection lost'); state.failRollback(rollbackError);
  await assert.rejects(state.journal.create(state.database, state.source, state.intent, async () => { checks += 1; if (checks === 2) throw Object.assign(new Error('authority changed'), { status: 401 }); }), error => error.status === 401);
  assert.equal(state.queries.at(-1).sql, 'ROLLBACK'); assert.ok(!state.queries.some(query => query.sql === 'COMMIT')); assert.deepEqual(state.releases, [rollbackError]);
});

test('invalid intents, expired sources, and missing verification fail before DML', async () => {
  const state = fixture();
  await assert.rejects(state.journal.create(state.database, state.source, { ...state.intent, bearer: 'forbidden' }, async () => {}), error => error.status === 400);
  await assert.rejects(state.journal.create(state.database, { ...state.source, validUntil: 1 }, state.intent, async () => {}), error => error.status === 401);
  await assert.rejects(state.journal.create(state.database, state.source, state.intent), error => error.status === 503);
  assert.equal(state.queries.length, 0);
});

test('ready defaults to the raw database and actually asks the receiver to verify itself', async () => {
  const state = fixture(); await state.journal.ready(); assert.equal(state.queries[0].sql, 'SELECT company_offboarding_receiving()');
});
