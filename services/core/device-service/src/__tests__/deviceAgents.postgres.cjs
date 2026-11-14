'use strict';
const { test, beforeEach, afterEach, after } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID, createHash } = require('node:crypto');
const { Pool } = require('pg');
const fs = require('node:fs');
const path = require('node:path');
const { DeviceInventory } = require('../DeviceInventory');
const { DeviceAgents, agentEtag } = require('../DeviceAgents');
const { DeviceCompliance, compliancePolicyEtag } = require('../DeviceCompliance');
const C = require('../../../../../packages/device-compliance-contract');
const { INVENTORY_PERMISSIONS } = require('../../../../../packages/device-inventory-contract');
assert.ok(process.env.DEVICE_TEST_DATABASE_URL);
const administration = new Pool({ connectionString: process.env.DEVICE_TEST_DATABASE_URL });
let pool, schema, db, source, inventory, agents, unit, revoked, compliance, canManage;
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
 agents = new DeviceAgents(db, { inventory }); canManage = true;
 compliance = new DeviceCompliance(db, { inventory, authority: { async read() { if (revoked) throw Object.assign(new Error('Original source revoked'), { status: 401 }); return { ...structuredClone(source), permissions: C.PERMISSIONS.slice(0, canManage ? 2 : 1) }; } } });
 unit = await inventory.create({ assetId: randomUUID(), serialNumber: randomUUID(), manufacturer: 'Native', model: 'Agent fixture', deviceClass: 'laptop', platform: 'linux' }, {}, 'Bearer original', randomUUID());
});
afterEach(async () => { await pool?.end(); await administration.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`); });
after(() => administration.end());
const get = () => agents.get(unit.id, {}, {}, 'Bearer original');
const manage = async (action = 'issue', revision) => agents.manage(unit.id, action, decision, agentEtag(unit.id, revision ?? (await get()).revision), {}, 'Bearer original', randomUUID());
const enroll = token => agents.register({ token, report }, randomUUID());
const heartbeat = token => agents.heartbeat({ deviceId: unit.id, report }, 'Bearer ' + token);
const hardware = () => ({ schemaVersion: 1, cpu: { model: 'Native fixture CPU', logicalProcessors: 8 }, memory: { totalBytes: '9007199254740993', availableBytes: '4000000000' }, systemDisk: { totalBytes: '1000000000000', availableBytes: '200000000000' }, uptimeSeconds: '86461' });
const systemReport = () => agents.inventoryReport(unit.id, {}, {}, 'Bearer original');
const hardwareHeartbeat = (token, inventory = hardware()) => agents.heartbeat({ deviceId: unit.id, report, inventory }, 'Bearer ' + token);
const security = (changes = {}) => ({ schemaVersion: 1, osVersion: '24.04', diskEncryption: { state: 'enabled', reason: 'checked' }, firewall: { state: 'enabled', reason: 'checked' }, ...changes });
const baseline = (changes = {}) => ({ ...C.DEFAULTS, enabled: true, minimumOsVersion: '22.04', requireDiskEncryption: true, requireFirewall: true, minimumDiskFreePercent: 10, ...changes });
const savePolicy = (settings = baseline(), revision = '0') => compliance.save('linux', { settings, reason: 'Explicit own company security baseline decision', confirm: true }, compliancePolicyEtag(source.tenant.id, 'linux', revision), {}, 'Bearer original', randomUUID());
const securityHeartbeat = (token, facts = security(), inventory = hardware()) => agents.heartbeat({ deviceId: unit.id, report, security: facts, inventory }, 'Bearer ' + token, randomUUID());
const assessment = () => compliance.get(unit.id, {}, {}, 'Bearer original');

test('company compliance policy starts unconfigured and requires a separate manager, exact revision and audit receipt', async () => {
 assert.equal((await assessment()).status, 'not-configured'); const policies = await compliance.policies({}, {}, 'Bearer original'); assert.equal(policies.policies.length, 3); assert.equal(policies.policies[0].revision, '0');
 canManage = false; await assert.rejects(savePolicy(), { status: 403 }); canManage = true;
 const saved = await savePolicy(); assert.equal(saved.policy.revision, '1'); assert.equal(saved.deliveryStatus, 'pending'); assert.equal((await assessment()).status, 'pending');
 await assert.rejects(savePolicy(), { status: 412 }); await assert.rejects(compliance.save('linux', { settings: baseline(), reason: decision.reason, confirm: true }, undefined, {}, 'Bearer original'), { status: 428 });
 const history = await compliance.history('linux', {}, {}, 'Bearer original', true); assert.equal(history.total, 1); assert.equal(history.events[0].actorUserId, source.actorUserId); assert.equal(history.events[0].deliveryStatus, 'pending');
});
test('actual security and exact disk evidence produce retained assessment transitions without one event per heartbeat', async () => {
 await savePolicy(); const registered = await enroll((await manage()).enrollmentToken);
 const failed = security({ firewall: { state: 'disabled', reason: 'checked' } });
 const response = await securityHeartbeat(registered.deviceToken, failed); assert.equal(response.compliance.status, 'non-compliant'); assert.equal(response.compliance.policyRevision, '1');
 let value = await assessment(); assert.equal(value.status, 'non-compliant'); assert.equal(value.assessment.checks.find(row => row.id === 'firewall').status, 'fail');
 assert.equal((await compliance.history(unit.id, {}, {}, 'Bearer original')).total, 1); await securityHeartbeat(registered.deviceToken, failed); assert.equal((await compliance.history(unit.id, {}, {}, 'Bearer original')).total, 1);
 await securityHeartbeat(registered.deviceToken); assert.equal((await assessment()).status, 'compliant');
 const unknown = security({ diskEncryption: { state: 'unknown', reason: 'probe-failed' } }); await securityHeartbeat(registered.deviceToken, unknown); assert.equal((await assessment()).status, 'unknown');
 const lowDisk = hardware(); lowDisk.systemDisk.availableBytes = '1'; await securityHeartbeat(registered.deviceToken, security(), lowDisk); assert.equal((await assessment()).status, 'non-compliant');
 value = await compliance.list({ status: 'non-compliant' }, {}, 'Bearer original'); assert.equal(value.total, 1); assert.equal(value.counts.total, 1); assert.equal(value.devices[0].deviceId, unit.id);
 assert.equal((await compliance.history(unit.id, {}, {}, 'Bearer original')).total, 4);
 assert.equal((await inventory.get(unit.id, {}, 'Bearer original')).revision, unit.revision);
});
test('changed policies await a new actual device report and numeric versions do not compare lexicographically', async () => {
 await savePolicy(baseline({ minimumOsVersion: '13.9' })); const registered = await enroll((await manage()).enrollmentToken);
 await securityHeartbeat(registered.deviceToken, security({ osVersion: '13.10' })); assert.equal((await assessment()).status, 'compliant');
 await savePolicy(baseline({ minimumOsVersion: '25.0' }), '1'); assert.equal((await assessment()).status, 'pending');
 await securityHeartbeat(registered.deviceToken); assert.equal((await assessment()).status, 'non-compliant');
 await savePolicy({ ...C.DEFAULTS }, '2'); assert.equal((await assessment()).status, 'not-configured');
});
test('revocation and replacement retain historical assessments, old heartbeats do not renew assessment age', async () => {
 await savePolicy(); const registered = await enroll((await manage()).enrollmentToken); await securityHeartbeat(registered.deviceToken); const first = (await assessment()).assessment;
 const old = await heartbeat(registered.deviceToken); assert.ok(!Object.hasOwn(old, 'compliance')); assert.deepEqual((await assessment()).assessment, first);
 await pool.query('ALTER TABLE device_agent_connections DISABLE TRIGGER USER'); try { await pool.query("UPDATE device_agent_connections SET compliance_report=jsonb_set(compliance_report,'{validUntil}',to_jsonb(clock_timestamp()-interval '1 second'))"); } finally { await pool.query('ALTER TABLE device_agent_connections ENABLE TRIGGER USER'); }
 assert.equal((await assessment()).status, 'stale'); await securityHeartbeat(registered.deviceToken); await manage('revoke'); assert.equal((await assessment()).status, 'historical');
 const replacement = await enroll((await manage()).enrollmentToken); assert.equal((await assessment()).status, 'historical'); await securityHeartbeat(replacement.deviceToken); assert.equal((await assessment()).status, 'compliant');
});
test('foreign selectors, fabricated source fields and invalid security cannot acquire a compliance result', async () => {
 await assert.rejects(compliance.list({ tenantId: source.tenant.id }, {}, 'Bearer original'), { status: 400 });
 await assert.rejects(compliance.get(unit.id, { force: 'true' }, {}, 'Bearer original'), { status: 400 });
 await assert.rejects(savePolicy(baseline({ minimumOsVersion: 'latest' })), { status: 400 });
 const registered = await enroll((await manage()).enrollmentToken);
 for (const facts of [null, { ...security(), tenantId: source.tenant.id }, security({ osVersion: '24.04\n' }), security({ firewall: { state: 'enabled', reason: 'probe-failed' } })]) await assert.rejects(securityHeartbeat(registered.deviceToken, facts), { status: 400 });
 source.tenant.id = randomUUID(); await assert.rejects(assessment(), { status: 404 }); assert.equal((await compliance.list({}, {}, 'Bearer original')).total, 0);
 revoked = true; await assert.rejects(assessment(), { status: 401 });
});
test('policy and assessment omissions or late row drift cannot acknowledge a successful physical commit', async () => {
 const event = await savePolicy(); const registered = await enroll((await manage()).enrollmentToken);
 await assert.rejects(pool.query('TRUNCATE device_compliance_policy_events CASCADE'), { code: '42501' }); await assert.rejects(pool.query('DELETE FROM device_compliance_policy_outbox'), { code: '42501' });
 await pool.query('CREATE FUNCTION omit_assessment() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL;END; $$; CREATE TRIGGER z_omit_assessment BEFORE INSERT ON device_compliance_events FOR EACH ROW EXECUTE FUNCTION omit_assessment()');
 await assert.rejects(securityHeartbeat(registered.deviceToken), { code: '42501' }); assert.equal((await assessment()).status, 'pending'); assert.equal((await compliance.history(unit.id, {}, {}, 'Bearer original')).total, 0);
 await pool.query('DROP TRIGGER z_omit_assessment ON device_compliance_events');
 await securityHeartbeat(registered.deviceToken); assert.equal((await assessment()).status, 'compliant');
 await pool.query('ALTER TABLE device_compliance_policy_outbox DISABLE TRIGGER device_compliance_policy_guard'); await assert.rejects(savePolicy(baseline({ requireFirewall: false }), event.policy.revision));
});

test('hardware heartbeat persists exact measured counters and server-owned receipt without mutating inventory or audit', async () => {
 assert.equal((await systemReport()).status, 'missing');
 const registered = await enroll((await manage()).enrollmentToken); assert.equal((await systemReport()).status, 'missing');
 await hardwareHeartbeat(registered.deviceToken);
 const result = await systemReport(); assert.equal(result.status, 'current'); assert.deepEqual(result.inventory.facts, hardware()); assert.equal(result.inventory.agentVersion, report.agentVersion);
 assert.ok(Date.parse(result.inventory.receivedAt) <= Date.parse(result.checkedAt)); assert.equal(result.inventory.revision, (await get()).revision);
 assert.equal((await inventory.get(unit.id, {}, 'Bearer original')).revision, unit.revision); assert.equal((await get()).history.total, 2);
 const receipt = result.inventory; await heartbeat(registered.deviceToken); assert.deepEqual((await systemReport()).inventory, receipt);
 const updated = hardware(); updated.memory = null; await hardwareHeartbeat(registered.deviceToken, updated); assert.equal((await systemReport()).inventory.facts.memory, null);
 assert.ok(!JSON.stringify(result).includes('_hash')); assert.ok(!JSON.stringify(result).includes(registered.deviceToken));
});
test('historical hardware is retained but never adopted by a newly issued or registered connection', async () => {
 const first = await enroll((await manage()).enrollmentToken); await hardwareHeartbeat(first.deviceToken); const receipt = (await systemReport()).inventory;
 await manage('revoke'); assert.equal((await systemReport()).status, 'historical'); assert.deepEqual((await systemReport()).inventory, receipt);
 const code = await manage(); assert.equal((await systemReport()).status, 'historical'); const current = await enroll(code.enrollmentToken);
 assert.equal((await systemReport()).status, 'historical'); await assert.rejects(hardwareHeartbeat(first.deviceToken), { status: 401 });
 await hardwareHeartbeat(current.deviceToken); assert.equal((await systemReport()).status, 'current'); assert.notEqual((await systemReport()).inventory.revision, receipt.revision);
});
test('hardware shape rejects unsafe counters, false measurements, added identity fields and caller timestamps at both boundaries', async () => {
 const { validateInventory } = require('../AgentInventory');
 const registered = await enroll((await manage()).enrollmentToken);
 const invalid = [null, {}, { ...hardware(), tenantId: source.tenant.id }, { ...hardware(), receivedAt: new Date().toISOString() }, { ...hardware(), memory: { totalBytes: 16, availableBytes: '1' } }, { ...hardware(), memory: { totalBytes: '0', availableBytes: '0' } }, { ...hardware(), systemDisk: { totalBytes: '10', availableBytes: '11' } }, { ...hardware(), uptimeSeconds: '1\n' }, { ...hardware(), uptimeSeconds: '9223372036854775808' }, { ...hardware(), cpu: { model: 'invalid\nmodel', logicalProcessors: 2 } }, { ...hardware(), cpu: { model: 'CPU', logicalProcessors: 1.5 } }];
 for (const value of invalid) {
  assert.throws(() => validateInventory(value), { status: 400 });
  assert.equal((await pool.query('SELECT device_agent_inventory_valid($1::jsonb) AS valid', [JSON.stringify(value)])).rows[0].valid, false);
  await assert.rejects(hardwareHeartbeat(registered.deviceToken, value), { status: 400 });
 }
 assert.equal((await systemReport()).status, 'missing');
});
test('hardware reads enforce the same own tenant, original live authority and exact selectors', async () => {
 await assert.rejects(agents.inventoryReport(unit.id, { tenantId: source.tenant.id }, {}, 'Bearer original'), { status: 400 });
 source.tenant.id = randomUUID(); await assert.rejects(systemReport(), { status: 404 });
 revoked = true; await assert.rejects(systemReport(), { status: 401 });
});
test('missing hardware receiver or late report drift prevents successful writes at physical commit', async () => {
 const registered = await enroll((await manage()).enrollmentToken);
 await assert.rejects(pool.query("UPDATE device_agent_connections SET inventory_report='{}'::jsonb"));
 await pool.query('ALTER TABLE device_agent_connections DROP CONSTRAINT device_agent_inventory_shape'); await assert.rejects(systemReport()); await assert.rejects(hardwareHeartbeat(registered.deviceToken));
 await pool.query(fs.readFileSync(path.join(__dirname, '../../migrations/009_agent_inventory.sql'), 'utf8'));
 await pool.query(`CREATE FUNCTION poison_hardware() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN NEW.inventory_report=jsonb_set(NEW.inventory_report,'{facts,memory,availableBytes}','"0"');RETURN NEW;END; $$; CREATE TRIGGER z_poison_hardware BEFORE UPDATE ON device_agent_connections FOR EACH ROW EXECUTE FUNCTION poison_hardware()`);
 await assert.rejects(hardwareHeartbeat(registered.deviceToken), { code: '42501' }); assert.equal((await systemReport()).status, 'missing');
});
test('hardware receipts survive migration replay and stale contact never presents live system data', async () => {
 const registered = await enroll((await manage()).enrollmentToken); await hardwareHeartbeat(registered.deviceToken); const original = (await systemReport()).inventory;
 for (const file of ['008_device_agents.sql','009_agent_inventory.sql']) await pool.query(fs.readFileSync(path.join(__dirname, '../../migrations', file), 'utf8'));
 assert.deepEqual((await systemReport()).inventory, original);
 // Only this disposable fixture moves the clock-bound rows; production guards stay active.
 await pool.query('ALTER TABLE device_agent_connections DISABLE TRIGGER USER');
 try { await pool.query(`UPDATE device_agent_connections SET last_seen=statement_timestamp()-interval '6 minutes',enrolled_at=statement_timestamp()-interval '1 hour',inventory_report=inventory_report||jsonb_build_object('enrolledAt',statement_timestamp()-interval '1 hour','receivedAt',statement_timestamp()-interval '6 minutes')`); }
 finally { await pool.query('ALTER TABLE device_agent_connections ENABLE TRIGGER USER'); }
 assert.equal((await systemReport()).status, 'stale');
});

test('fleet reads real agent status and counts in one own-tenant snapshot without changing inventory', async () => {
 const registered = await enroll((await manage()).enrollmentToken); await heartbeat(registered.deviceToken);
 const other = await inventory.create({ assetId: 'FLEET-SECOND', serialNumber: randomUUID(), manufacturer: 'Native', model: 'Second', deviceClass: 'laptop', platform: 'linux' }, {}, 'Bearer original');
 const fleet = await agents.fleet({}, {}, 'Bearer original');
 assert.equal(fleet.fleet.counts.total, 2); assert.equal(fleet.fleet.counts.connected, 1); assert.equal(fleet.fleet.counts['not-enrolled'], 1);
 const connected = fleet.fleet.connections.find(row => row.deviceId === unit.id); assert.equal(connected.status, 'connected'); assert.deepEqual(connected.report, report); assert.ok(Date.parse(connected.lastSeen) <= Date.parse(fleet.fleet.checkedAt));
 assert.equal(fleet.devices.find(row => row.id === unit.id).lastSeen, null); assert.equal(fleet.devices.find(row => row.id === unit.id).revision, unit.revision);
 const filtered = await agents.fleet({ connectionStatus: 'connected', search: unit.assetId }, {}, 'Bearer original');
 assert.equal(filtered.total, 1); assert.equal(filtered.fleet.counts.total, 1); assert.equal(filtered.devices[0].id, unit.id);
 const unconnected = await agents.fleet({ connectionStatus: 'not-enrolled' }, {}, 'Bearer original'); assert.deepEqual(unconnected.devices.map(row => row.id), [other.id]); assert.equal(unconnected.fleet.counts.total, 2);
 assert.ok(!JSON.stringify(fleet).includes('_hash')); assert.ok(!JSON.stringify(fleet).includes(registered.deviceToken));
 source.tenant.id = randomUUID(); assert.equal((await agents.fleet({}, {}, 'Bearer original')).total, 0);
 revoked = true; await assert.rejects(agents.fleet({}, {}, 'Bearer original'), { status: 401 });
});
test('fleet status cutoff, expired and revoked states agree with device detail and CSV filters', async () => {
 await enroll((await manage()).enrollmentToken);
 // Controlled timestamps in this disposable schema only; production row guards remain enabled.
 async function drift(values) { await pool.query('ALTER TABLE device_agent_connections DISABLE TRIGGER USER'); try { await pool.query('UPDATE device_agent_connections SET '+values); } finally { await pool.query('ALTER TABLE device_agent_connections ENABLE TRIGGER USER'); } }
 await drift("last_seen=clock_timestamp()-interval '4 minutes'"); assert.equal((await get()).status, 'offline');
 assert.equal((await agents.fleet({ connectionStatus: 'offline' }, {}, 'Bearer original')).total, 1);
 await drift("credential_expires_at=clock_timestamp()-interval '1 second'"); assert.equal((await get()).status, 'expired');
 assert.equal((await agents.fleet({}, {}, 'Bearer original')).fleet.counts.expired, 1);
 await manage('revoke'); assert.equal((await agents.fleet({}, {}, 'Bearer original')).fleet.counts.revoked, 1);
 await manage(); assert.equal((await agents.fleet({}, {}, 'Bearer original')).fleet.counts.pending, 1);
 const exported = await agents.fleet({ connectionStatus: 'pending' }, {}, 'Bearer original', true); assert.equal(exported.count, 1); assert.match(exported.csv, /"connectionStatus","lastSeen","hostname","agentVersion"/); assert.match(exported.csv, /"pending"/);
 const empty = await agents.fleet({ connectionStatus: 'connected' }, {}, 'Bearer original', true); assert.equal(empty.count, 0); assert.equal(empty.csv.split('\r\n').length, 2);
 await drift("bootstrap_expires_at=clock_timestamp()-interval '1 second'"); assert.equal((await agents.fleet({}, {}, 'Bearer original')).fleet.counts.expired, 1);
});
test('fleet validates exact selectors, pagination, CSV escaping and current authority after the read', async () => {
 for (const query of [{ tenantId: source.tenant.id }, { connectionStatus: ['connected'] }, { connectionStatus: 'all' }, { connectionStatus: '' }, { page: '0' }, { sort: 'hostname' }]) await assert.rejects(agents.fleet(query, {}, 'Bearer original'), { status: 400 });
 await assert.rejects(agents.fleet({ page: '1' }, {}, 'Bearer original', true), { status: 400 });
 const created = await inventory.create({ assetId: '=DANGEROUS()', serialNumber: randomUUID(), manufacturer: 'Native', model: 'Quoted "model"', deviceClass: 'laptop', platform: 'linux' }, {}, 'Bearer original');
 const one = await agents.fleet({ sort: 'assetId', order: 'asc', limit: '1' }, {}, 'Bearer original'); assert.equal(one.devices.length, 1); assert.equal(one.total, 2);
 const two = await agents.fleet({ sort: 'assetId', order: 'asc', page: '2', limit: '1' }, {}, 'Bearer original'); assert.equal(two.devices.length, 1); assert.deepEqual(new Set([one.devices[0].id, two.devices[0].id]), new Set([unit.id, created.id]));
 const csv = await agents.fleet({}, {}, 'Bearer original', true); assert.match(csv.csv, /"'=DANGEROUS\(\)"/); assert.match(csv.csv, /"Quoted ""model"""/);
 const checkpoint = inventory.checkpoint.bind(inventory); inventory.checkpoint = async (...args) => { revoked = true; return checkpoint(...args); };
 await assert.rejects(agents.fleet({}, {}, 'Bearer original'), { status: 401 });
});
test('a heartbeat committed after transaction begin but before snapshot acquisition is valid fleet evidence', async () => {
 const registered = await enroll((await manage()).enrollmentToken);
 const transaction = db.transaction.bind(db); let observed = false;
 db.transaction = (operation, options = {}) => transaction(async client => {
  if (options.readOnly && !observed) { observed = true; await new Promise(resolve => setTimeout(resolve, 30)); await heartbeat(registered.deviceToken); }
  return operation(client);
 }, options);
 const fleet = await agents.fleet({}, {}, 'Bearer original'); assert.equal(fleet.fleet.counts.connected, 1); assert.ok(Date.parse(fleet.fleet.connections[0].lastSeen) <= Date.parse(fleet.fleet.checkedAt));
});

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
  const measured = await systemReport(); assert.equal(measured.status, 'current'); assert.equal(measured.inventory.agentVersion, '1.3.0'); assert.ok(Number(measured.inventory.facts.cpu.logicalProcessors) > 0); assert.ok(BigInt(measured.inventory.facts.memory.totalBytes) > 0n);
  const unconfigured=await run('compliance');assert.equal(unconfigured.code,1);assert.match(unconfigured.output,/not-configured/);
  await compliance.save(platform,{settings:{...C.DEFAULTS,enabled:true,minimumOsVersion:'0'},reason:'Validate the actual Rust OS observation with a bounded fixture rule',confirm:true},compliancePolicyEtag(source.tenant.id,platform,'0'),{},'Bearer original',randomUUID());
  const checked=await run('compliance');assert.equal(checked.code,0,checked.output);const actualAssessment=await assessment();assert.equal(actualAssessment.status,'compliant');assert.equal(actualAssessment.assessment.security.agentVersion,'1.3.0');assert.ok(C.security(actualAssessment.assessment.security.facts));
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

test('concurrent current-version policy writers serialize and retain only the winning receipt', async () => {
 const results=await Promise.allSettled([savePolicy(baseline({minimumOsVersion:'22.04'})),savePolicy(baseline({minimumOsVersion:'24.04'}))]);
 assert.equal(results.filter(result=>result.status==='fulfilled').length,1);assert.equal(results.find(result=>result.status==='rejected').reason.status,412);
 const history=await compliance.history('linux',{}, {},'Bearer original',true);assert.equal(history.total,1);assert.equal(history.events[0].after.revision,'1');
});
test('policy source expiry during physical commit rolls back policy, retained event and pending outbox', async () => {
 const original=db.transaction;db.transaction=(operation,options={})=>original(operation,{...options,beforeCommit:async client=>{if(options.beforeCommit)await options.beforeCommit(client);const proof=(await client.query("SELECT current_setting('opendirectory.device_compliance_policy',true) AS proof")).rows[0].proof;if(proof){await client.query("SELECT set_config('opendirectory.device_compliance_policy',jsonb_set($1::jsonb,'{validUntil}',to_jsonb(extract(epoch FROM clock_timestamp())-1))::text,true)",[proof]);}}});
 await assert.rejects(savePolicy(),{code:'42501'});assert.equal((await compliance.policies({}, {},'Bearer original')).policies.find(row=>row.platform==='linux').revision,'0');assert.equal((await compliance.history('linux',{}, {},'Bearer original',true)).total,0);
});

test('compliance migration replay retains the actual policy, assessments and exact large policy history revisions', async () => {
 await savePolicy();const registered=await enroll((await manage()).enrollmentToken);await securityHeartbeat(registered.deviceToken);const retained=(await assessment()).assessment;
 await pool.query(fs.readFileSync(path.join(__dirname,'../../migrations/010_device_compliance.sql'),'utf8'));assert.deepEqual((await assessment()).assessment,retained);assert.equal((await compliance.history(unit.id,{}, {},'Bearer original')).total,1);
 await pool.query('ALTER TABLE device_compliance_policies DISABLE TRIGGER USER');try{await pool.query("UPDATE device_compliance_policies SET revision=9007199254740993 WHERE tenant_id=$1 AND platform='linux'",[source.tenant.id]);}finally{await pool.query('ALTER TABLE device_compliance_policies ENABLE TRIGGER USER');}
 const saved=await savePolicy(baseline({minimumOsVersion:'24.04'}),'9007199254740993');assert.equal(saved.policy.revision,'9007199254740994');const history=await compliance.history('linux',{}, {},'Bearer original',true);assert.equal(history.events[0].before.revision,'9007199254740993');assert.equal(history.events[0].after.revision,'9007199254740994');
 await securityHeartbeat(registered.deviceToken);assert.equal((await assessment()).policyRevision,'9007199254740994');
});
