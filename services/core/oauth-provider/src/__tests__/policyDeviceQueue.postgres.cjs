'use strict';
const { test, before, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const fs = require('node:fs'); const path = require('node:path'); const { Pool } = require('pg');
const { PolicyDeviceQueue, operator } = require('../PolicyDeviceQueue');
const contract = require('../../../../../packages/policy-command-contract');
const schema = 'device_policy_' + randomUUID().replaceAll('-', '');
const administration = new Pool({ connectionString: process.env.OAUTH_TEST_DATABASE_URL, max: 1 });
const userId = randomUUID(); const deviceId = 'owned-policy-device';
const authorization = 'Bearer very-private-original-credential'; const deviceAuthorization = 'Bearer very-private-device-credential';
let pool; let database; let queue; let user; let agent; let state; let reference;
function actor(id = userId, roles = ['policy-deployment-operator']) {
  const authTime = Math.floor(Date.now() / 1000);
  return { actor_type: 'user', token_use: 'access', iss: 'https://owned-issuer.test', sub: 'owned-' + id, client_id: 'owned-client', jti: randomUUID(), exp: authTime + 3600, auth_time: authTime,
    roles, identity_authorization: { userId: id, revision: '1', linkRevision: '1', rolesRevision: 'a'.repeat(64) }, amr: ['pwd','otp'],
    mfa_authorization: { schemaVersion: 1, userId: id, revision: '1', authTime, methods: ['pwd','otp'] } };
}
async function sourceFrame(body, claims) {
  state.sources++; if (state.sourceHook) await state.sourceHook(state.sources);
  const payload = { blueprintId: body.reference.resourceId, blueprintName: 'Owned approved blueprint', configurationId: body.reference.configurationId,
    configurationVersion: body.reference.resourceVersion, configType: 'screen_lock', configName: 'Owned screen lock', settings: { minutes: 5, privateSetting: 'not-copied-to-command-audit' } };
  const hash = (await pool.query("SELECT encode(sha256(convert_to($1::jsonb::text,'UTF8')),'hex') AS hash", [JSON.stringify(payload)])).rows[0].hash;
  const now = Date.now(); const until = Math.min(now + 290000, claims.exp * 1000, (claims.auth_time + 300) * 1000);
  if(state.badPayload)payload.settings.minutes=999;
  return { schemaVersion: 1, ...body, operatorUserId: claims.identity_authorization.userId, configurationVersion: 3, configurationHash: state.configurationHash,
    publicationVersion: 2, publicationExpiresAt: new Date(state.publicationExpiry).toISOString(), observedAt: new Date(now).toISOString(),
    admissionValidUntil: new Date(Math.min(now + 30000, until)).toISOString(), deliverUntil: new Date(until).toISOString(), payload, payloadHash: hash };
}
const enqueue = (operation = randomUUID(), who = user, body = { command: 'update_policy', reference }) => queue.queue(deviceId, body, operation, who, authorization);
const poll = (who = agent) => queue.pending(deviceId, who, deviceAuthorization);
const cancellationReason = 'Withdraw this exact owned device command';
const cancel = (accepted, operationId = randomUUID(), who = user, reason = cancellationReason) => queue.cancel(deviceId, accepted.id, { policyReceipt: accepted.policyReceipt, reason, acknowledgeScope: true }, operationId, who, authorization);
const history = (who = user, extra = {}) => queue.ownedHistory({ resourceKind: reference.resourceKind, resourceId: reference.resourceId, limit: 200, offset: 0, ...extra }, who, authorization);
before(async () => {
  await administration.query(`CREATE SCHEMA ${schema}`); const url = new URL(process.env.OAUTH_TEST_DATABASE_URL); url.searchParams.set('options', `-c search_path=${schema},public`);
  pool = new Pool({ connectionString: url.toString(), max: 8 }); database = { pool, query: (...args) => pool.query(...args), isAvailable: () => true };
  for (const file of ['001_initial_schema.sql','002_mdm_commands.sql','012_policy_device_commands.sql','013_policy_command_cancellations.sql']) await pool.query(fs.readFileSync(path.join(__dirname, '../../migrations', file), 'utf8'));
});
beforeEach(async () => {
  database.isAvailable = () => true;
  await pool.query("CREATE OR REPLACE FUNCTION policy_device_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp(); $$");
  await pool.query('TRUNCATE policy_device_command_outbox,policy_device_command_audit,policy_device_operations,mdm_commands,enrolled_devices CASCADE');
  await pool.query("INSERT INTO enrolled_devices(id,hostname,platform,status) VALUES($1,'Owned receiver test','windows','active')", [deviceId]);
  user = actor(); agent = { token_use: 'device', sub: deviceId, platform: 'windows', iss: 'https://owned-issuer.test', aud: 'opendirectory-device-agent', jti: randomUUID(), exp: Math.floor(Date.now() / 1000) + 3600 };
  agent.device_generation=String((await pool.query('SELECT policy_generation FROM enrolled_devices WHERE id=$1',[deviceId])).rows[0].policy_generation);
  reference = { resourceKind: 'blueprint', resourceId: randomUUID(), resourceVersion: 3, publicationId: randomUUID(), configurationId: randomUUID() };
  state = { sources: 0, sourceHook: null, checks: 0, checkHook: null, userRevoked: false, deviceRevoked: false, configurationHash: 'b'.repeat(64), publicationExpiry: Date.now() + 600000 };
  queue = new PolicyDeviceQueue(database, { isUserRevoked: async () => { state.checks++; if (state.checkHook) await state.checkHook(state.checks); return state.userRevoked; },
    isDeviceRevoked: async () => {state.deviceChecks=(state.deviceChecks||0)+1;if(state.deviceHook)await state.deviceHook(state.deviceChecks);return state.deviceRevoked;}, source: { frame: sourceFrame } });
});
after(async () => { if (pool) await pool.end(); await administration.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`); await administration.end(); });
test('a policy command is a committed source-bound SQL receipt with immutable original actor, audit and pending outbox, not an in-memory acknowledgement', async () => {
  const result = await enqueue(); assert.equal(result.status, 'pending'); assert.equal(result.enforcementConfirmed, false); assert.equal(result.policyReceipt.persistence, 'committed');
  assert.equal(result.policyReceipt.operatorUserId, userId); assert.deepEqual(result.policyReceipt.reference, reference); assert.equal(state.sources, 2);
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM policy_device_operations')).rows[0].count, 1);
  const audit = (await pool.query('SELECT * FROM policy_device_command_audit')).rows;
  assert.equal(audit[0].actor.userId, userId); assert.equal(JSON.stringify(audit).includes('not-copied-to-command-audit'), false); assert.equal(JSON.stringify(audit).includes('very-private-original-credential'), false);
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM policy_device_command_outbox')).rows[0].count, 1);
});
test('free payloads, spoofed actors, missing operations, ordinary users and stale MFA cannot enter the persistent queue', async () => {
  await assert.rejects(enqueue(randomUUID(), user, { command: 'update_policy', reference, payload: { arbitrary: true } }), { status: 400 });
  await assert.rejects(enqueue(undefined, actor(randomUUID(), ['user'])), { status: 403 });
  const weak = { ...user, amr: ['pwd'], mfa_authorization: undefined }; await assert.rejects(enqueue(undefined, weak), { status: 428 });
  await assert.rejects(queue.queue(deviceId, { command: 'update_policy', reference }, undefined, user, authorization), { status: 400 });
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM mdm_commands')).rows[0].count, 0);
});
test('a post-DML original operator loss rolls back command, retained operation origin, audit and outbox together', async () => {
  state.checkHook = async count => { if (count === 3) state.userRevoked = true; }; await assert.rejects(enqueue(), { status: 401 });
  for (const table of ['mdm_commands','policy_device_operations','policy_device_command_audit','policy_device_command_outbox']) assert.equal((await pool.query(`SELECT count(*)::int AS count FROM ${table}`)).rows[0].count, 0);
});
test('a source change or source outage after command DML cannot leave an accepted queue row', async () => {
  state.sourceHook = async count => { if (count === 2) state.configurationHash = 'c'.repeat(64); }; await assert.rejects(enqueue(), { status: 409 });
  state.sources = 0; state.sourceHook = async count => { if (count === 2) throw new contract.PolicyCommandError(503, 'owned_source_outage'); }; await assert.rejects(enqueue(), { status: 503 });
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM mdm_commands')).rows[0].count, 0);
});
test('mandatory command audit failure cannot return a stored or memory-success receipt', async () => {
  await pool.query('ALTER TABLE policy_device_command_audit RENAME TO owned_missing_command_audit');
  try { await assert.rejects(enqueue(), { status: 503 }); } finally { await pool.query('ALTER TABLE owned_missing_command_audit RENAME TO policy_device_command_audit'); }
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM mdm_commands')).rows[0].count, 0);
});
test('concurrent identical operation retries have one command and cannot extend its deadline or duplicate acceptance evidence', async () => {
  const operation = randomUUID(); const results = await Promise.all([enqueue(operation), enqueue(operation)]); assert.equal(results[0].id, results[1].id); assert.equal(results[0].policyReceipt.expiresAt, results[1].policyReceipt.expiresAt);
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM mdm_commands')).rows[0].count, 1); assert.equal((await pool.query('SELECT count(*)::int AS count FROM policy_device_command_audit')).rows[0].count, 1);
  let release;const gate=new Promise(resolve=>{release=resolve;});state.sources=0;state.sourceHook=async count=>{if(count===1)await gate;};const pending=Array.from({length:4},()=>enqueue());
  try{for(let attempt=0;attempt<200&&queue.activeTransactions<4;attempt++)await new Promise(resolve=>setTimeout(resolve,10));assert.equal(queue.activeTransactions,4);
   assert.equal((await pool.query('SELECT 1 AS healthy')).rows[0].healthy,1);await assert.rejects(enqueue(),{status:503,code:'policy_command_capacity_unavailable'});
  }finally{release();await Promise.all(pending);}
  assert.equal(queue.activeTransactions,0);assert.equal((await pool.query('SELECT count(*)::int AS count FROM mdm_commands')).rows[0].count,5);
});
test('an operation cannot borrow another operator or adopt a different captured source even with independently valid permissions', async () => {
  const operation = randomUUID(); await enqueue(operation); await assert.rejects(enqueue(operation, actor(randomUUID())), { status: 409 });
  state.configurationHash = 'c'.repeat(64); await assert.rejects(enqueue(operation), { status: 409 });
});
test('a current subject-bound device pulls durable policy commands across fresh service instances; administrator and other-device tokens cannot impersonate it', async () => {
  const accepted = await enqueue(); await assert.rejects(poll(user), { status: 403 }); await assert.rejects(poll({ ...agent, sub: 'other-device' }), { status: 403 });
  const first = await poll(); assert.equal(first.length, 1); assert.equal(first[0].id, accepted.id); assert.ok(first[0].dispatchedAt); assert.equal(first[0].enforcementConfirmed, false);
  const fresh = new PolicyDeviceQueue(database, { isDeviceRevoked: async () => false }); const again = await fresh.pending(deviceId, agent, deviceAuthorization); assert.equal(again[0].id, first[0].id);
  assert.deepEqual((await pool.query('SELECT action FROM policy_device_command_audit ORDER BY version')).rows.map(row => row.action), ['queued','dispatched','dispatched']);
});
test('only a dispatched command has one terminal bounded device report; reported success is not independently confirmed execution', async () => {
  const accepted = await enqueue(); const report = { status: 'completed', result: { reported: true } };
  await assert.rejects(queue.report(deviceId, accepted.id, report, agent, deviceAuthorization), { status: 409 }); await poll();
  const reported = await queue.report(deviceId, accepted.id, report, agent, deviceAuthorization); assert.equal(reported.status, 'completed'); assert.equal(reported.enforcementConfirmed, false);
  assert.equal((await queue.report(deviceId, accepted.id, report, agent, deviceAuthorization)).id, accepted.id);
  await assert.rejects(queue.report(deviceId, accepted.id, { status: 'failed', result: {} }, agent, deviceAuthorization), { status: 409 }); assert.deepEqual(await poll(), []);
});
test('device credential revocation and enrollment/platform reincarnation stop pending delivery without relabeling old commands current', async () => {
  await enqueue(); state.deviceRevoked = true; await assert.rejects(poll(), { status: 401 }); state.deviceRevoked = false;
  await pool.query("UPDATE enrolled_devices SET platform='linux' WHERE id=$1", [deviceId]); await assert.rejects(poll(), { status: 403 });
  await assert.rejects(poll({ ...agent, platform: 'linux' }), { status: 403 });
  const generation=String((await pool.query('SELECT policy_generation FROM enrolled_devices WHERE id=$1',[deviceId])).rows[0].policy_generation);
  assert.deepEqual(await poll({ ...agent, platform: 'linux', device_generation:generation }), []); assert.equal((await queue.list(deviceId)).commands[0].status, 'expired');
});
test('raw SQL cannot enqueue unapproved policy content, edit an accepted payload, delete history or forge audit/outbox/origins', async () => {
  await assert.rejects(pool.query("INSERT INTO mdm_commands(id,device_id,command,payload) VALUES('forged',$1,'update_policy','{}')", [deviceId]), error => error.code === '42501');
  await enqueue();
  for (const sql of ["UPDATE mdm_commands SET payload='{}' WHERE command='update_policy'", 'DELETE FROM mdm_commands', 'DELETE FROM policy_device_operations', 'DELETE FROM policy_device_command_audit', 'DELETE FROM policy_device_command_outbox']) await assert.rejects(pool.query(sql), error => ['42501','23514'].includes(error.code));
});
test('known admission expiry after the final issuer check is rejected by the real deferred commit without extending the observed source lease', async () => {
  await pool.query('CREATE TABLE owned_policy_clock(seconds integer NOT NULL);INSERT INTO owned_policy_clock VALUES(0)');
  await pool.query("CREATE OR REPLACE FUNCTION policy_device_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+seconds*interval '1 second' FROM owned_policy_clock; $$");
  state.checkHook = async count => { if (count === 3) await pool.query('UPDATE owned_policy_clock SET seconds=31'); };
  try { await assert.rejects(enqueue(), { status: 409 }); assert.equal((await pool.query('SELECT count(*)::int AS count FROM mdm_commands')).rows[0].count, 0); }
  finally { await pool.query("CREATE OR REPLACE FUNCTION policy_device_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp(); $$;DROP TABLE owned_policy_clock"); }
});
test('pending policy commands are not offered after their known delivery horizon, without a sweeper or fake completion', async () => {
  await enqueue(); await pool.query("CREATE OR REPLACE FUNCTION policy_device_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+interval '301 seconds'; $$");
  assert.deepEqual(await poll(), []); const record = (await queue.list(deviceId)).commands[0]; assert.equal(record.status, 'expired'); assert.equal(record.completedAt, null);
  assert.deepEqual((await pool.query('SELECT action FROM policy_device_command_audit')).rows.map(row => row.action), ['queued']);
});
test('migration replay preserves command identity, original generation, deadlines and approval evidence without restamping old acceptance', async () => {
  const accepted = await enqueue(); const before = (await pool.query('SELECT * FROM mdm_commands')).rows; const generations = (await pool.query('SELECT policy_generation FROM enrolled_devices')).rows;
  for (const file of ['012_policy_device_commands.sql','013_policy_command_cancellations.sql']) await pool.query(fs.readFileSync(path.join(__dirname, '../../migrations', file), 'utf8'));
  assert.deepEqual((await pool.query('SELECT * FROM mdm_commands')).rows, before); assert.deepEqual((await pool.query('SELECT policy_generation FROM enrolled_devices')).rows, generations); assert.equal((await poll())[0].id, accepted.id);
});
test('the SQL receiver checks the actual payload digest instead of trusting a well-shaped but inconsistent source frame',async()=>{
 state.badPayload=true;await assert.rejects(enqueue(),{status:503});assert.equal((await pool.query('SELECT count(*)::int AS count FROM mdm_commands')).rows[0].count,0);
});
test('an original actor revoked while waiting on the actual enrolled-device row cannot commit the earlier admission',async()=>{
 const blocker=await pool.connect();let pending;
 try{await blocker.query('BEGIN');await blocker.query('SELECT id FROM enrolled_devices WHERE id=$1 FOR UPDATE',[deviceId]);pending=enqueue();pending.catch(()=>{});let waiting=false;
 for(let attempt=0;attempt<200;attempt++){waiting=(await pool.query("SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'SELECT id,platform,status,policy_generation FROM enrolled_devices%FOR UPDATE'")).rows.length>0;if(waiting)break;await new Promise(resolve=>setTimeout(resolve,10));}assert.equal(waiting,true);state.userRevoked=true;await blocker.query('COMMIT');await assert.rejects(pending,{status:401});assert.equal((await pool.query('SELECT count(*)::int AS count FROM mdm_commands')).rows[0].count,0);
 }finally{await blocker.query('ROLLBACK');blocker.release();if(pending)await pending.catch(()=>{});}
});
test('device credentials without a captured generation cannot use policy polling even when their device ID and signature purpose are otherwise valid',async()=>{
 await enqueue();const legacy={...agent};delete legacy.device_generation;await assert.rejects(poll(legacy),{status:403});assert.equal((await pool.query('SELECT policy_dispatched_at FROM mdm_commands')).rows[0].policy_dispatched_at,null);
});
test('a failing device-report audit cannot change the command or fabricate a completed result',async()=>{
 const accepted=await enqueue();await poll();await pool.query('ALTER TABLE policy_device_command_audit RENAME TO owned_report_audit_missing');
 try{await assert.rejects(queue.report(deviceId,accepted.id,{status:'completed',result:'Device claimed success'},agent,deviceAuthorization),{status:503});}finally{await pool.query('ALTER TABLE owned_report_audit_missing RENAME TO policy_device_command_audit');}
 const row=(await pool.query('SELECT status,result,completed_at FROM mdm_commands')).rows[0];assert.deepEqual(row,{status:'pending',result:null,completed_at:null});
});
test('known operator JWT and MFA cutoffs after the last source check are independently enforced at the actual queue commit',async()=>{
 await pool.query('CREATE TABLE owned_actor_clock(seconds integer NOT NULL);INSERT INTO owned_actor_clock VALUES(0)');await pool.query("CREATE OR REPLACE FUNCTION policy_device_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+seconds*interval '1 second' FROM owned_actor_clock; $$");
 try{user.exp=Math.floor(Date.now()/1000)+10;state.checkHook=async count=>{if(count===3)await pool.query('UPDATE owned_actor_clock SET seconds=11');};await assert.rejects(enqueue(),{status:401});
 await pool.query('UPDATE owned_actor_clock SET seconds=0');state.checks=0;user.exp=Math.floor(Date.now()/1000)+3600;state.checkHook=async count=>{if(count===3)await pool.query('UPDATE owned_actor_clock SET seconds=301');};await assert.rejects(enqueue(),{status:428});assert.equal((await pool.query('SELECT count(*)::int AS count FROM mdm_commands')).rows[0].count,0);
 }finally{await pool.query("CREATE OR REPLACE FUNCTION policy_device_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp(); $$;DROP TABLE owned_actor_clock");}
});
test('device credential expiry after dispatch audit DML cannot commit a new offer or disclose it as current',async()=>{
 await enqueue();agent.exp=Math.floor(Date.now()/1000)+10;await pool.query('CREATE TABLE owned_device_clock(seconds integer NOT NULL);INSERT INTO owned_device_clock VALUES(0)');await pool.query("CREATE OR REPLACE FUNCTION policy_device_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+seconds*interval '1 second' FROM owned_device_clock; $$");
 state.deviceHook=async count=>{if(count===3)await pool.query('UPDATE owned_device_clock SET seconds=11');};
 try{await assert.rejects(poll(),{status:401});assert.equal((await pool.query('SELECT policy_dispatched_at FROM mdm_commands')).rows[0].policy_dispatched_at,null);assert.equal((await pool.query('SELECT count(*)::int AS count FROM policy_device_command_audit')).rows[0].count,1);}
 finally{await pool.query("CREATE OR REPLACE FUNCTION policy_device_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp(); $$;DROP TABLE owned_device_clock");}
});
test('legacy pending commands remain unverified history and cannot be relabeled as approved device offers by migration replay',async()=>{
 const legacy=schema+'_old';await administration.query(`CREATE SCHEMA ${legacy}`);const url=new URL(process.env.OAUTH_TEST_DATABASE_URL);url.searchParams.set('options',`-c search_path=${legacy},public`);const older=new Pool({connectionString:url.toString(),max:2});
 try{for(const file of ['001_initial_schema.sql','002_mdm_commands.sql'])await older.query(fs.readFileSync(path.join(__dirname,'../../migrations',file),'utf8'));await older.query("INSERT INTO enrolled_devices(id,platform,status) VALUES($1,'windows','active')",[deviceId]);await older.query("INSERT INTO mdm_commands(id,device_id,command,payload) VALUES('legacy-command',$1,'update_policy','{\"unverified\":true}')",[deviceId]);await older.query(fs.readFileSync(path.join(__dirname,'../../migrations/012_policy_device_commands.sql'),'utf8'));
 const historical=new PolicyDeviceQueue({pool:older,query:(...args)=>older.query(...args),isAvailable:()=>true},{isDeviceRevoked:async()=>false});const generation=String((await older.query('SELECT policy_generation FROM enrolled_devices')).rows[0].policy_generation);
 assert.deepEqual(await historical.pending(deviceId,{...agent,device_generation:generation},deviceAuthorization),[]);const rows=(await historical.list(deviceId)).commands;assert.equal(rows[0].status,'legacy-unverified');assert.equal(rows[0].payloadOmitted,true);assert.equal((await older.query('SELECT count(*)::int AS count FROM policy_device_command_audit')).rows[0].count,0);
 }finally{await older.end();await administration.query(`DROP SCHEMA ${legacy} CASCADE`);}
});
test('owned cancellation commits one retained reason, original receipt, current human actor, derived audit and outbox without claiming reversed execution', async () => {
  const accepted = await enqueue(); const operationId = randomUUID(); const result = await cancel(accepted, operationId);
  assert.deepEqual(result.policyReceipt, accepted.policyReceipt); assert.equal(result.operationId, operationId); assert.equal(result.cancelledByUserId, userId);
  assert.equal(result.furtherOffersStopped, true); assert.equal(result.previouslyOffered, false); assert.equal(result.enforcementConfirmed, false);
  const row = (await pool.query('SELECT * FROM mdm_commands')).rows[0]; assert.equal(row.status, 'cancelled'); assert.equal(row.completed_at, null); assert.equal(row.result, null); assert.deepEqual(row.payload, accepted.payload);
  const evidence = (await pool.query('SELECT * FROM policy_device_cancellations')).rows[0]; assert.equal(evidence.reason, cancellationReason); assert.equal(evidence.actor.tokenId, user.jti);
  assert.equal(JSON.stringify(evidence).includes('very-private-original-credential'), false); assert.equal((await pool.query('SELECT count(*)::int AS count FROM policy_device_command_outbox')).rows[0].count, 2);
  assert.deepEqual((await pool.query('SELECT action FROM policy_device_command_audit ORDER BY version')).rows.map(row => row.action), ['queued','cancelled']);
  assert.deepEqual(await poll(), []); await assert.rejects(queue.report(deviceId, accepted.id, { status: 'completed', result: {} }, agent, deviceAuthorization), { status: 409 });
});
test('cancellation is owned by the original canonical human, not a global administrator, reviewer, application, device or internal alias', async () => {
  const accepted = await enqueue(); await assert.rejects(cancel(accepted, undefined, actor(randomUUID(), ['admin'])), { status: 404 });
  for (const candidate of [actor(randomUUID(), ['policy-publication-reviewer']), actor(userId, ['user']), { ...user, actor_type: 'application' }, agent]) await assert.rejects(cancel(accepted, undefined, candidate), { status: 403 });
  await assert.rejects(cancel(accepted, undefined, { ...user, amr: ['pwd'], mfa_authorization: undefined }), { status: 428 });
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM policy_device_cancellations')).rows[0].count, 0);
});
test('a renewed current session of the same canonical human can cancel without storing or reviving the original bearer or source approval', async () => {
  const accepted = await enqueue(); const renewed = actor(); state.sourceHook = () => { throw new Error('Cancellation must not borrow source admission'); };
  const result = await cancel(accepted, undefined, renewed); assert.equal(result.cancelledByUserId, userId); assert.equal(state.sources, 2);
  assert.equal((await pool.query('SELECT actor FROM policy_device_cancellations')).rows[0].actor.tokenId, renewed.jti);
});
test('cancellation binds the exact committed receipt and rejects free actors, unknown fields, malformed references and missing operation capture', async () => {
  const accepted = await enqueue(); const body = { policyReceipt: accepted.policyReceipt, reason: cancellationReason, acknowledgeScope: true };
  await assert.rejects(queue.cancel(deviceId, accepted.id, { ...body, actor: userId }, randomUUID(), user, authorization), { status: 400 });
  await assert.rejects(queue.cancel(deviceId, accepted.id, { ...body, policyReceipt: {} }, randomUUID(), user, authorization), { status: 400 });
  await assert.rejects(queue.cancel(deviceId, accepted.id, body, undefined, user, authorization), { status: 400 });
  for (const changed of [{ payloadHash: 'f'.repeat(64) }, { deviceGeneration: '999' }, { reference: { ...reference, resourceVersion: 4 } }]) {
    await assert.rejects(queue.cancel(deviceId, accepted.id, { ...body, policyReceipt: { ...accepted.policyReceipt, ...changed } }, randomUUID(), user, authorization), { status: 409 });
  }
  for (const reason of ['', 'short', ' leading justification', 'x'.repeat(501), 'Invalid\u0000reason here']) await assert.rejects(cancel(accepted, undefined, user, reason), { status: 400 });
  assert.equal((await pool.query('SELECT status FROM mdm_commands')).rows[0].status, 'pending');
});
test('same captured cancellation retries survive fresh service instances without new evidence or changed operation ownership', async () => {
  const accepted = await enqueue(); const operationId = randomUUID(); const results = await Promise.all([cancel(accepted, operationId), cancel(accepted, operationId)]);
  assert.deepEqual(results[0], results[1]); const fresh = new PolicyDeviceQueue(database, { isUserRevoked: async () => false });
  assert.deepEqual(await fresh.cancel(deviceId, accepted.id, { policyReceipt: accepted.policyReceipt, reason: cancellationReason, acknowledgeScope: true }, operationId, actor(), authorization), results[0]);
  await assert.rejects(cancel(accepted), { status: 409 }); await assert.rejects(cancel(accepted, operationId, user, 'A different cancellation justification'), { status: 409 });
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM policy_device_command_audit')).rows[0].count, 2);
});
test('a cancellation operation cannot be reused for a second command and rolls that attempted transition back', async () => {
  const first = await enqueue(); const second = await enqueue(); const operationId = randomUUID(); await cancel(first, operationId);
  await assert.rejects(cancel(second, operationId), { status: 409 }); assert.equal((await pool.query('SELECT status FROM mdm_commands WHERE id=$1', [second.id])).rows[0].status, 'pending');
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM policy_device_cancellations')).rows[0].count, 1);
});
test('cancelling an already offered command stops further polls and reports but retains its actual device offer evidence', async () => {
  const accepted = await enqueue(); await poll(); const result = await cancel(accepted); assert.equal(result.previouslyOffered, true); assert.equal(result.enforcementConfirmed, false);
  const row = (await pool.query('SELECT * FROM mdm_commands')).rows[0]; assert.ok(row.policy_dispatched_at); assert.equal(row.policy_delivery_actor.kind, 'device'); assert.equal(row.completed_at, null);
  assert.deepEqual(await poll(), []); await assert.rejects(queue.report(deviceId, accepted.id, { status: 'completed', result: 'already received' }, agent, deviceAuthorization), { status: 409 });
});
test('completed or failed device results cannot be relabeled as cancelled or erased by their original deployer', async () => {
  for (const status of ['completed','failed']) {
    const accepted = await enqueue(); await poll(); await queue.report(deviceId, accepted.id, { status, result: { device: 'reported' } }, agent, deviceAuthorization);
    await assert.rejects(cancel(accepted), { status: 409 }); assert.equal((await pool.query('SELECT status FROM mdm_commands WHERE id=$1', [accepted.id])).rows[0].status, status);
  }
});
test('expired or previous-generation commands can be explicitly stopped without requiring a currently deliverable device or source', async () => {
  user.exp = Math.floor(Date.now() / 1000) + 10; const accepted = await enqueue(); user = actor();
  await pool.query("UPDATE enrolled_devices SET platform='linux',status='retired' WHERE id=$1", [deviceId]);
  await pool.query("CREATE OR REPLACE FUNCTION policy_device_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+interval '11 seconds'; $$");
  const result = await cancel(accepted); assert.equal(result.furtherOffersStopped, true); assert.equal(result.policyReceipt.deviceGeneration, accepted.policyReceipt.deviceGeneration);
});
test('original authority loss after cancellation DML rolls back status, retained cancellation, audit and outbox together', async () => {
  const accepted = await enqueue(); state.checks = 0; state.checkHook = count => { if (count === 3) state.userRevoked = true; };
  await assert.rejects(cancel(accepted), { status: 401 }); assert.equal((await pool.query('SELECT status FROM mdm_commands')).rows[0].status, 'pending');
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM policy_device_cancellations')).rows[0].count, 0); assert.equal((await pool.query('SELECT count(*)::int AS count FROM policy_device_command_outbox')).rows[0].count, 1);
});
test('missing cancellation evidence or mandatory audit fails closed instead of acknowledging a stopped device command', async () => {
  const accepted = await enqueue();
  for (const table of ['policy_device_cancellations','policy_device_command_audit','policy_device_command_outbox']) {
    await pool.query(`ALTER TABLE ${table} RENAME TO owned_missing_evidence`);
    try { await assert.rejects(cancel(accepted), { status: 503 }); } finally { await pool.query(`ALTER TABLE owned_missing_evidence RENAME TO ${table}`); }
    assert.equal((await pool.query('SELECT status FROM mdm_commands')).rows[0].status, 'pending');
  }
});
test('raw cancellation writes, forged retained evidence, deletion, payload replacement and reopening a cancelled command are rejected', async () => {
  const accepted = await enqueue(); await assert.rejects(pool.query("UPDATE mdm_commands SET status='cancelled' WHERE id=$1", [accepted.id]), error => error.code === '42501');
  for (const changed of [{ actor: operator(actor(randomUUID(), ['admin']), authorization) }, { receipt: { ...accepted.policyReceipt, payloadHash: 'f'.repeat(64) } }, { alterPayload: true }]) {
    const client = await pool.connect();
    try {
      await client.query('BEGIN'); await queue.proof(client, { action: 'cancelled', commandId: accepted.id, operationId: randomUUID(), actor: operator(user, authorization), receipt: accepted.policyReceipt, reason: cancellationReason, ...changed });
      await assert.rejects(client.query(changed.alterPayload ? "UPDATE mdm_commands SET status='cancelled',payload='{}' WHERE id=$1" : "UPDATE mdm_commands SET status='cancelled' WHERE id=$1", [accepted.id]), error => ['42501','23514'].includes(error.code));
    } finally { await client.query('ROLLBACK'); client.release(); }
  }
  await cancel(accepted);
  for (const sql of ["UPDATE mdm_commands SET status='pending'", "UPDATE mdm_commands SET payload='{}'", 'DELETE FROM mdm_commands', 'DELETE FROM policy_device_cancellations', "UPDATE policy_device_cancellations SET reason='Rewritten reason by raw SQL'", 'INSERT INTO policy_device_cancellations SELECT * FROM policy_device_cancellations'])
    await assert.rejects(pool.query(sql), error => ['42501','23514'].includes(error.code));
});
test('owned SQL command history includes immutable stale-version receipts and cancellation evidence but no payload or another operator commands', async () => {
  const accepted = await enqueue(); await cancel(accepted); await enqueue(undefined, actor(randomUUID()));
  const result = await history(); assert.equal(result.contract, 'owned-policy-cancellation-v1'); assert.equal(result.commands.length, 1); assert.equal(result.truncated, false);
  assert.deepEqual(result.commands[0].policyReceipt, accepted.policyReceipt); assert.equal(result.commands[0].status, 'cancelled'); assert.equal(result.commands[0].cancellationReceipt.furtherOffersStopped, true);
  assert.equal(JSON.stringify(result).includes('not-copied-to-command-audit'), false); assert.equal(JSON.stringify(result).includes('very-private-original-credential'), false);
  assert.deepEqual((await history(actor(randomUUID(), ['admin']))).commands, []); assert.deepEqual((await history(user, { resourceId: randomUUID() })).commands, []);
});
test('owned command history is bounded, paginated, exact-scope and refuses weak authority or unavailable storage', async () => {
  await enqueue(); await enqueue(); assert.equal((await history(user, { limit: 1 })).truncated, true); assert.equal((await history(user, { limit: 1, offset: 1 })).truncated, false);
  for (const query of [{ limit: 201 }, { offset: -1 }, { resourceId: 'guess' }, { resourceKind: 'all' }, { extra: 'actor' }]) await assert.rejects(history(user, query), { status: 400 });
  await assert.rejects(history(actor(userId, ['policy-reader'])), { status: 403 }); state.userRevoked = true; await assert.rejects(history(), { status: 401 }); state.userRevoked = false;
  database.isAvailable = () => false; await assert.rejects(history(), { status: 503 });
});
test('cancellation JWT and MFA deadlines are enforced by deferred SQL commit after the final live authority check', async () => {
  const accepted = await enqueue(); await pool.query('CREATE TABLE owned_cancel_clock(seconds integer NOT NULL);INSERT INTO owned_cancel_clock VALUES(0)');
  await pool.query("CREATE OR REPLACE FUNCTION policy_device_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+seconds*interval '1 second' FROM owned_cancel_clock; $$");
  try {
    state.checks = 0; user.exp = Math.floor(Date.now() / 1000) + 10; state.checkHook = async count => { if (count === 3) await pool.query('UPDATE owned_cancel_clock SET seconds=11'); };
    await assert.rejects(cancel(accepted), { status: 401 }); await pool.query('UPDATE owned_cancel_clock SET seconds=0'); state.checks = 0; user.exp += 3600;
    state.checkHook = async count => { if (count === 3) await pool.query('UPDATE owned_cancel_clock SET seconds=301'); };
    await assert.rejects(cancel(accepted), { status: 428 }); assert.equal((await pool.query('SELECT status FROM mdm_commands')).rows[0].status, 'pending');
    assert.equal((await pool.query('SELECT count(*)::int AS count FROM policy_device_cancellations')).rows[0].count, 0);
  } finally { await pool.query("CREATE OR REPLACE FUNCTION policy_device_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp(); $$;DROP TABLE owned_cancel_clock"); }
});
test('migration upgrade and replay preserve cancelled status, actor, receipt, reason and existing evidence without reopening commands', async () => {
  const accepted = await enqueue(); await poll(); const cancelled = await cancel(accepted); const evidence = (await pool.query('SELECT * FROM policy_device_cancellations')).rows;
  for (const file of ['012_policy_device_commands.sql','013_policy_command_cancellations.sql']) await pool.query(fs.readFileSync(path.join(__dirname, '../../migrations', file), 'utf8'));
  assert.deepEqual((await pool.query('SELECT * FROM policy_device_cancellations')).rows, evidence); assert.deepEqual((await history()).commands[0].cancellationReceipt, cancelled);
  assert.deepEqual(await poll(), []); await assert.rejects(queue.queue(deviceId, { command: 'update_policy', reference }, accepted.policyReceipt.operationId, user, authorization), { status: 409 });
  const upgrade = schema + '_upgrade'; await administration.query(`CREATE SCHEMA ${upgrade}`); const url = new URL(process.env.OAUTH_TEST_DATABASE_URL); url.searchParams.set('options', `-c search_path=${upgrade},public`);
  const older = new Pool({ connectionString: url.toString(), max: 3 });
  try {
    for (const file of ['001_initial_schema.sql','002_mdm_commands.sql','012_policy_device_commands.sql']) await older.query(fs.readFileSync(path.join(__dirname, '../../migrations', file), 'utf8'));
    await older.query("INSERT INTO enrolled_devices(id,platform,status) VALUES($1,'windows','active')", [deviceId]);
    const previous = new PolicyDeviceQueue({ pool: older, query: (...args) => older.query(...args), isAvailable: () => true }, { isUserRevoked: async () => false, isDeviceRevoked: async () => false, source: { frame: sourceFrame } });
    const prior = await previous.queue(deviceId, { command: 'update_policy', reference }, randomUUID(), user, authorization);
    const credential = { ...agent, device_generation: String((await older.query('SELECT policy_generation FROM enrolled_devices')).rows[0].policy_generation) };
    await previous.pending(deviceId, credential, deviceAuthorization); const before = (await older.query('SELECT * FROM mdm_commands')).rows;
    await older.query(fs.readFileSync(path.join(__dirname, '../../migrations/013_policy_command_cancellations.sql'), 'utf8'));
    assert.deepEqual((await older.query('SELECT * FROM mdm_commands')).rows, before); assert.equal((await older.query('SELECT count(*)::int AS count FROM policy_device_cancellations')).rows[0].count, 0);
    const stopped = await previous.cancel(deviceId, prior.id, { policyReceipt: prior.policyReceipt, reason: cancellationReason, acknowledgeScope: true }, randomUUID(), user, authorization);
    assert.equal(stopped.previouslyOffered, true); assert.deepEqual(stopped.policyReceipt, prior.policyReceipt);
    for (const file of ['012_policy_device_commands.sql','013_policy_command_cancellations.sql']) await older.query(fs.readFileSync(path.join(__dirname, '../../migrations', file), 'utf8'));
    assert.deepEqual(await previous.pending(deviceId, credential, deviceAuthorization), []); assert.equal((await older.query('SELECT count(*)::int AS count FROM policy_device_command_audit')).rows[0].count, 3);
  } finally { await older.end(); await administration.query(`DROP SCHEMA ${upgrade} CASCADE`); }
});
test('cancellation and concurrent device polling serialize on the actual device and never offer a command after cancellation commits', async () => {
  const accepted = await enqueue(); const [cancelled, offered] = await Promise.all([cancel(accepted), poll()]);
  assert.equal(cancelled.previouslyOffered, offered.length === 1); if (offered.length) assert.equal(offered[0].id, accepted.id);
  assert.deepEqual(await poll(), []); assert.equal((await history()).commands[0].status, 'cancelled');
});
test('an operator revoked behind the real cancellation device-row lock cannot stop a command using its earlier authority observation', async () => {
  const accepted = await enqueue(); const blocker = await pool.connect(); let pending;
  try {
    await blocker.query('BEGIN'); await blocker.query('SELECT id FROM enrolled_devices WHERE id=$1 FOR UPDATE', [deviceId]); pending = cancel(accepted); pending.catch(() => {});
    let waiting = false;
    for (let attempt = 0; attempt < 200; attempt++) {
      waiting = (await pool.query("SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query='SELECT id FROM enrolled_devices WHERE id=$1 FOR UPDATE'")).rows.length > 0;
      if (waiting) break; await new Promise(resolve => setTimeout(resolve, 10));
    }
    assert.equal(waiting, true); state.userRevoked = true; await blocker.query('COMMIT'); await assert.rejects(pending, { status: 401 });
    assert.equal((await pool.query('SELECT status FROM mdm_commands')).rows[0].status, 'pending');
  } finally { await blocker.query('ROLLBACK'); blocker.release(); if (pending) await pending.catch(() => {}); }
});
