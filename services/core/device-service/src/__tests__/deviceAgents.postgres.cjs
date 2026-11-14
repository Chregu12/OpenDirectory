'use strict';
const { test, beforeEach, afterEach, after } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID, createHash } = require('node:crypto');
const { Pool } = require('pg');
const fs = require('node:fs');
const path = require('node:path');
const { DeviceInventory } = require('../DeviceInventory');
const { DeviceAgents, agentEtag } = require('../DeviceAgents');
const { INVENTORY_PERMISSIONS } = require('../../../../../packages/device-inventory-contract');
assert.ok(process.env.DEVICE_TEST_DATABASE_URL);
const administration = new Pool({ connectionString: process.env.DEVICE_TEST_DATABASE_URL });
let pool, schema, db, source, inventory, agents, unit, revoked;
const report = { hostname: 'actual-fixture', platform: 'linux', architecture: 'x86_64', osVersion: 'Linux', agentVersion: '1.1.0' };
const decision = { reason: 'Native explicit enrollment decision', confirm: true };
beforeEach(async () => {
 schema = 'agent_' + randomUUID().replaceAll('-', ''); await administration.query(`CREATE SCHEMA ${schema}`);
 const url = new URL(process.env.DEVICE_TEST_DATABASE_URL); url.searchParams.set('options', `-c search_path=${schema}`); pool = new Pool({ connectionString: url.toString(), max: 5 });
 for (const file of fs.readdirSync(path.join(__dirname, '../../migrations')).filter(file => file.endsWith('.sql')).sort()) await pool.query(fs.readFileSync(path.join(__dirname, '../../migrations', file), 'utf8'));
 db = { isAvailable: () => true, async transaction(operation, { readOnly = false, beforeCommit } = {}) { const client = await pool.connect(); try { await client.query(readOnly ? 'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY' : 'BEGIN'); const value = await operation(client); if (beforeCommit) await beforeCommit(client); await client.query('COMMIT'); return value; } catch (error) { await client.query('ROLLBACK'); throw error; } finally { client.release(); } } };
 revoked = false; const now = Math.floor(Date.now() / 1000); const actor = randomUUID();
 source = { schemaVersion: 1, issuer: 'https://native.example', subject: actor, tokenId: randomUUID(), expiresAt: now + 3600,
  context: { userId: actor, revision: '1', linkRevision: '1', rolesRevision: 'a'.repeat(64) }, tenant: { id: randomUUID(), version: '1', generation: '1' }, actorUserId: actor, permissions: [...INVENTORY_PERMISSIONS], validUntil: now + 300, target: null };
 inventory = new DeviceInventory(db, { authority: { async read() { if (revoked) throw Object.assign(new Error('Original authority revoked'), { status: 401 }); return structuredClone(source); } } });
 agents = new DeviceAgents(db, { inventory });
 unit = await inventory.create({ assetId: randomUUID(), serialNumber: randomUUID(), manufacturer: 'Native', model: 'Agent fixture', deviceClass: 'laptop', platform: 'linux' }, {}, 'Bearer original', randomUUID());
});
afterEach(async () => { await pool?.end(); await administration.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`); });
after(() => administration.end());
const get = () => agents.get(unit.id, {}, {}, 'Bearer original');
const manage = async (action = 'issue', revision) => agents.manage(unit.id, action, decision, agentEtag(unit.id, revision ?? (await get()).revision), {}, 'Bearer original', randomUUID());
const enroll = token => agents.register({ token, report }, randomUUID());
const heartbeat = token => agents.heartbeat({ deviceId: unit.id, report }, 'Bearer ' + token);

test('real persisted enrollment, heartbeat and revocation remain separate from inventory and assignment', async () => {
 assert.equal((await get()).status, 'not-enrolled');
 const issued = await manage(); assert.match(issued.enrollmentToken, /^odae_[A-Za-z0-9_-]{43}$/); assert.equal(issued.connection.status, 'pending');
 const registered = await enroll(issued.enrollmentToken); assert.match(registered.deviceToken, /^odad_[A-Za-z0-9_-]{43}$/);
 assert.equal((await get()).status, 'connected'); await heartbeat(registered.deviceToken);
 const state = await get(); assert.deepEqual(state.report, report); assert.equal(state.history.total, 2); assert.deepEqual(state.history.events.map(row => row.action), ['register', 'issue']);
 assert.equal((await inventory.get(unit.id, {}, 'Bearer original')).revision, unit.revision);
 const stored = JSON.stringify((await pool.query('SELECT to_jsonb(c) AS state FROM device_agent_connections c')).rows) + JSON.stringify((await pool.query('SELECT * FROM device_agent_events')).rows);
 assert.ok(!stored.includes(issued.enrollmentToken)); assert.ok(!stored.includes(registered.deviceToken)); assert.ok(!JSON.stringify(state).includes('_hash'));
 assert.equal((await manage('revoke')).status, 'revoked'); await assert.rejects(heartbeat(registered.deviceToken), { status: 401 });
 assert.equal((await get()).history.total, 3);
});
test('single-use enrollment is serialized: concurrent registration yields exactly one credential', async () => {
 const issued = await manage(); const results = await Promise.allSettled([enroll(issued.enrollmentToken), enroll(issued.enrollmentToken)]);
 assert.equal(results.filter(result => result.status === 'fulfilled').length, 1); assert.equal((await get()).history.total, 2);
 await assert.rejects(enroll(issued.enrollmentToken));
});
test('reissuing revokes the old device credential and previous pending code', async () => {
 const a = await manage(); const old = await enroll(a.enrollmentToken); const b = await manage();
 await assert.rejects(heartbeat(old.deviceToken), { status: 401 });
 const c = await manage(); await assert.rejects(enroll(b.enrollmentToken), { status: 401 });
 const current = await enroll(c.enrollmentToken); await heartbeat(current.deviceToken);
});
test('stale or missing revisions, unconfirmed decisions and unknown selectors are rejected', async () => {
 await manage(); await assert.rejects(manage('issue', '0'), { status: 412 });
 await assert.rejects(agents.manage(unit.id, 'issue', decision, undefined, {}, 'Bearer original'), { status: 428 });
 await assert.rejects(agents.manage(unit.id, 'issue', { ...decision, confirm: false }, agentEtag(unit.id, '1'), {}, 'Bearer original'), { status: 400 });
 await assert.rejects(agents.get(unit.id, { tenantId: source.tenant.id }, {}, 'Bearer original'), { status: 400 });
});
test('foreign tenants and withdrawn original human authority cannot read or issue a device connection', async () => {
 source.tenant.id = randomUUID(); await assert.rejects(get(), { status: 404 }); await assert.rejects(manage(), { status: 404 });
 revoked = true; await assert.rejects(get(), { status: 401 });
});
test('physical source expiry rolls back state and audit at commit', async () => {
 const original = inventory.checkpoint.bind(inventory); let calls = 0;
 inventory.checkpoint = async (...args) => { await original(...args); if (++calls === 2) { await pool.query('SELECT pg_sleep(1.2)'); } };
 source.validUntil = Math.floor(Date.now() / 1000) + 1;
 await assert.rejects(manage('issue', '0'));
 assert.equal((await pool.query('SELECT count(*) FROM device_agent_connections')).rows[0].count, '0');
 assert.equal((await pool.query('SELECT count(*) FROM device_agent_events')).rows[0].count, '0');
});
test('raw writes, truncation and missing receiving guards fail closed', async () => {
 const issued = await manage();
 await assert.rejects(pool.query("UPDATE device_agent_connections SET credential_hash=repeat('a',64)"), { code: '42501' });
 await assert.rejects(pool.query('DELETE FROM device_agent_events'), { code: '42501' });
 await assert.rejects(pool.query('TRUNCATE device_agent_connections CASCADE'), { code: '42501' });
 await pool.query('ALTER TABLE device_agent_events DISABLE TRIGGER device_agent_guard'); await assert.rejects(enroll(issued.enrollmentToken));
});
test('device credentials cannot select another device or report a different platform', async () => {
 const issued = await manage(); await assert.rejects(agents.register({ token: issued.enrollmentToken, report: { ...report, platform: 'windows' } }, randomUUID()));
 const connection = await enroll(issued.enrollmentToken);
 await assert.rejects(agents.heartbeat({ deviceId: randomUUID(), report }, 'Bearer ' + connection.deviceToken), { status: 401 });
 await assert.rejects(agents.heartbeat({ deviceId: unit.id, report: { ...report, tenantId: source.tenant.id } }, 'Bearer ' + connection.deviceToken), { status: 400 });
 await assert.rejects(heartbeat('human.jwt'), { status: 401 });
});
test('expired bootstrap and device credentials are rejected using server time', async () => {
 const issued = await manage();
 async function expire(column) {
  // Deliberate clock-drift fixture in a disposable schema; production guards stay enabled.
  await pool.query('ALTER TABLE device_agent_connections DISABLE TRIGGER USER');
  try { await pool.query(`UPDATE device_agent_connections SET ${column}=clock_timestamp()-interval '1 second'`); }
  finally { await pool.query('ALTER TABLE device_agent_connections ENABLE TRIGGER USER'); }
 }
 await expire('bootstrap_expires_at'); await assert.rejects(enroll(issued.enrollmentToken), { status: 401 }); assert.equal((await get()).status, 'expired');
 const next = await manage(); const current = await enroll(next.enrollmentToken); await expire('credential_expires_at');
 await assert.rejects(heartbeat(current.deviceToken), { status: 401 }); assert.equal((await get()).status, 'expired');
});

test('active agent connections must be revoked before maintenance, archival or platform changes', async () => {
 await manage(); const { deviceEtag } = require('../../../../../packages/device-inventory-contract');
 for (const lifecycle of ['maintenance','retired']) await assert.rejects(inventory.lifecycle(unit.id, { lifecycle, reason: 'Native confirmed device lifecycle transition', confirm: true }, deviceEtag(unit), {}, 'Bearer original'), { code: '23514' });
 await manage('revoke'); const result = await inventory.lifecycle(unit.id, { lifecycle: 'retired', reason: 'Native confirmed device lifecycle transition', confirm: true }, deviceEtag(unit), {}, 'Bearer original'); assert.equal(result.lifecycle, 'retired');
});

test('actual Rust binary enrolls through HTTP gateway, stores a private credential, heartbeats and detects revocation', { skip: !process.env.DEVICE_AGENT_BINARY }, async () => {
 const { spawn } = require('node:child_process'); const os = require('node:os');
 const { createInventoryApp } = require('../inventoryServer'); const { deviceAgentProxy } = require('../../../api-gateway/src/middleware/deviceAgentProxy');
 const express = require('express');
 const platform = process.platform === 'darwin' ? 'macos' : process.platform === 'win32' ? 'windows' : 'linux';
 if (platform !== unit.platform) unit = await inventory.update(unit.id, { assetId: unit.assetId, serialNumber: unit.serialNumber, manufacturer: unit.manufacturer, model: unit.model, deviceClass: unit.deviceClass, platform, reason: 'Actual native Rust client host platform', confirm: true }, require('../../../../../packages/device-inventory-contract').deviceEtag(unit), {}, 'Bearer original', randomUUID());
 const receiver = createInventoryApp({ db, inventory, agents, returns: {} }).listen(0, '127.0.0.1'); await new Promise(resolve => receiver.once('listening', resolve));
 const gateway = express(); gateway.use(deviceAgentProxy('http://127.0.0.1:' + receiver.address().port)); gateway.use((_req, res) => res.status(401).json({ error: 'Human authentication required' }));
 const server = gateway.listen(0, '127.0.0.1'); await new Promise(resolve => server.once('listening', resolve));
 const folder = fs.mkdtempSync(path.join(os.tmpdir(), 'od-agent-rust-')); const configPath = path.join(folder, 'agent.json');
 const issued = await manage(); const endpoint = 'http://127.0.0.1:' + server.address().port;
 async function run(command, enrollment) {
  return new Promise((resolve, reject) => {
   const child = spawn(process.env.DEVICE_AGENT_BINARY, ['--server-url', endpoint, command], { env: { ...process.env, OD_CONFIG_PATH: configPath, OD_ENROLLMENT_TOKEN: enrollment || '' } });
   let output = ''; child.stdout.on('data', chunk => { output += chunk; }); child.stderr.on('data', chunk => { output += chunk; }); child.once('error', reject); child.once('exit', code => resolve({ code, output }));
  });
 }
 try {
  assert.equal((await run('enroll', issued.enrollmentToken)).code, 0);
  const stored = JSON.parse(fs.readFileSync(configPath, 'utf8')); assert.equal(stored.enrollment_token, null); assert.match(stored.device_token, /^odad_/); assert.equal(stored.device_id, unit.id);
  if (process.platform !== 'win32') assert.equal(fs.statSync(configPath).mode & 0o777, 0o600);
  assert.equal((await run('heartbeat')).code, 0); assert.equal((await get()).status, 'connected');
  assert.equal((await fetch(endpoint + '/api/devices', { headers: { Authorization: 'Bearer ' + stored.device_token } })).status, 401);
  assert.equal((await fetch(endpoint + '/api/device-agent/heartbeat?deviceId=foreign', { method: 'POST' })).status, 404);
  await manage('revoke'); const denied = await run('heartbeat'); assert.equal(denied.code, 1); assert.match(denied.output, /401/); assert.ok(!denied.output.includes(stored.device_token));
 } finally { await Promise.all([new Promise(resolve => receiver.close(resolve)), new Promise(resolve => server.close(resolve))]); fs.rmSync(folder, { recursive: true, force: true }); }
});

test('clearing the command context before physical commit rolls back connection and retained event', async () => {
 const transaction = db.transaction.bind(db);
 db.transaction = (operation, options = {}) => transaction(operation, { ...options, beforeCommit: options.readOnly ? options.beforeCommit : async client => {
  if (options.beforeCommit) await options.beforeCommit(client);
  await client.query("SELECT set_config('opendirectory.device_agent','',true)");
 } });
 await assert.rejects(manage('issue', '0'), { code: '42501' });
 assert.equal((await pool.query('SELECT count(*) FROM device_agent_connections')).rows[0].count, '0');
 assert.equal((await pool.query('SELECT count(*) FROM device_agent_events')).rows[0].count, '0');
});
test('reapplying the additive agent migration preserves existing credentials and audit history', async () => {
 const issued = await manage(); const current = await enroll(issued.enrollmentToken);
 await pool.query(fs.readFileSync(path.join(__dirname, '../../migrations/008_device_agents.sql'), 'utf8'));
 await heartbeat(current.deviceToken); assert.equal((await get()).history.total, 2);
});
