'use strict';

const { test, before, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('crypto');
const fs = require('fs');
const path = require('path');
const http = require('http');
const express = require('express');
const { Pool } = require('pg');
const { generateKeyPair, SignJWT, jwtVerify, exportJWK } = require('jose');
const { LicenseAllocator } = require('../LicenseAllocator');
const { GroupLicenseAllocator } = require('../GroupLicenseAllocator');
const { GroupSnapshotClient } = require('../GroupSnapshotClient');
const { GroupSnapshotStore } = require('../../../../identity-service/src/GroupSnapshotStore');
const { UserSnapshotStore } = require('../../../../identity-service/src/UserSnapshotStore');
const { requireIdentityAccess } = require('../../../../identity-service/src/middleware/identityAccess');

const connectionString = process.env.LICENSE_TEST_DATABASE_URL;
test('a proof expiring behind the actual pool lock cannot create or renew any directory lease',async()=>{
 const license=await product();const groupId=await group([await person()]);await grant(license,groupId);const before=(await pool.query('SELECT * FROM license_group_observations')).rows;const blocker=await pool.connect();let pending;
 try{await blocker.query('BEGIN');await blocker.query('SELECT id FROM license_catalog WHERE id=$1 FOR UPDATE',[license.id]);pending=reconcile(license,groupId);pending.catch(()=>{});let waiting=false;
 for(let attempt=0;attempt<200;attempt++){waiting=(await pool.query("SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'SELECT * FROM license_catalog WHERE id = %'")).rows.length>0;if(waiting)break;await new Promise(resolve=>setTimeout(resolve,10));}assert.equal(waiting,true);
 await pool.query("CREATE OR REPLACE FUNCTION license_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+interval '301 seconds'; $$");await blocker.query('COMMIT');await assert.rejects(pending,{status:409});assert.deepEqual((await pool.query('SELECT * FROM license_group_observations')).rows,before);assert.equal(await allocator.count(pool,license.id),0);
 }finally{await blocker.query('ROLLBACK');blocker.release();if(pending)await pending.catch(()=>{});}
});
test('a new canonical user generation cannot silently inherit an older group projection origin',async()=>{
 const license=await product();const recipient=await person();const groupId=await group([recipient]);await grant(license,groupId);await direct(license,recipient);const before=(await pool.query('SELECT * FROM license_group_observations')).rows;
 await directory.query('UPDATE users SET enabled=false WHERE id=$1',[recipient]);await directory.query('UPDATE users SET enabled=true WHERE id=$1',[recipient]);
 await assert.rejects(reconcile(license,groupId),{status:409});assert.deepEqual((await pool.query('SELECT * FROM license_group_observations')).rows,before);
 const authentication=await context();await allocator.users.reconcile(recipient,'manager',authentication);await assert.rejects(reconcile(license,groupId),{status:409});
 await allocator.revoke(license.id,recipient,'manager','user');await groups.revoke(license.id,groupId,'manager');await grant(license,groupId);
 const assignment=(await pool.query('SELECT * FROM license_assignments')).rows[0];const canonical=(await directory.query('SELECT eligibility_revision FROM users WHERE id=$1',[recipient])).rows[0];assert.equal(assignment.eligibility_revision,canonical.eligibility_revision);
});
test('directory leases physically cap actual canonical group seats and release capacity without a source poll or expiry sweep',async()=>{
 const recipient=await person();const license=await product(1);const groupId=await group([recipient]);await grant(license,groupId);
 const assignment=(await pool.query('SELECT * FROM license_assignments WHERE license_id=$1',[license.id])).rows[0];
 const observation=(await pool.query('SELECT * FROM license_group_observations')).rows[0];
 assert.equal(assignment.expires_at.getTime(),observation.valid_until.getTime());assert.equal(observation.valid_until-observation.observed_at,300000);
 assert.equal((await pool.query('SELECT expires_at FROM license_assignment_sources')).rows[0].expires_at,null);
 sourceMode='group-offline';await pool.query("CREATE OR REPLACE FUNCTION license_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+interval '301 seconds'; $$");
 assert.equal(await allocator.count(pool,license.id),0);assert.equal((await pool.query('SELECT count(*)::int AS count FROM license_assignments')).rows[0].count,1);
 const read=await api('GET','/groups','manager','license-reader');assert.equal(read.status,200);assert.equal(read.body.groups[0].status,'directory-stale');assert.equal(read.body.groups[0].assigned_users,0);
 await direct(license,await person());assert.equal(await allocator.count(pool,license.id),1);
});
test('renewing a live directory lease extends only the projection, not business grant identity or its conditional version',async()=>{
 const recipient=await person();const license=await product();const groupId=await group([recipient]);await grant(license,groupId);
 const grantBefore=(await pool.query('SELECT * FROM license_grants')).rows;const before=(await pool.query('SELECT * FROM license_group_observations')).rows[0];
 await reconcile(license,groupId);const after=(await pool.query('SELECT * FROM license_group_observations')).rows[0];
 assert.equal(after.version,String(BigInt(before.version)+1n));assert.ok(after.valid_until>before.valid_until);assert.equal(after.source_hash,before.source_hash);
 assert.deepEqual((await pool.query('SELECT * FROM license_grants')).rows,grantBefore);
 const read=await api('GET','/groups','manager','license-reader');assert.equal(read.body.groups[0].directory_valid_until,after.valid_until.toISOString());
});
test('an identical live observation is idempotent and cannot manufacture renewal evidence',async()=>{
 const license=await product();const groupId=await group([await person()]);const snapshot=await client.snapshot(groupId,(await context()).authorization);sourceMode=()=>snapshot;await grant(license,groupId);
 const before=(await pool.query('SELECT * FROM license_group_lease_audit ORDER BY id')).rows;await reconcile(license,groupId);
 assert.deepEqual((await pool.query('SELECT * FROM license_group_lease_audit ORDER BY id')).rows,before);assert.equal((await pool.query('SELECT version FROM license_group_observations')).rows[0].version,'1');
});
test('older observations of the same directory revision cannot renew a newer projection',async()=>{
 const license=await product();const groupId=await group([await person()]);const old=await client.snapshot(groupId,(await context()).authorization);await grant(license,groupId);
 const before=(await pool.query('SELECT * FROM license_group_observations')).rows;sourceMode=()=>old;await assert.rejects(reconcile(license,groupId),{status:409});
 assert.deepEqual((await pool.query('SELECT * FROM license_group_observations')).rows,before);
});
test('replaying an observation past its physical cutoff cannot restore a group right',async()=>{
 const license=await product();const groupId=await group([await person()]);const old=await client.snapshot(groupId,(await context()).authorization);sourceMode=()=>old;await grant(license,groupId);
 await pool.query("CREATE OR REPLACE FUNCTION license_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+interval '301 seconds'; $$");
 await assert.rejects(reconcile(license,groupId),{status:409});assert.equal(await allocator.count(pool,license.id),0);assert.equal((await pool.query('SELECT version FROM license_group_observations')).rows[0].version,'1');
});
test('membership response deadlines cap the projection earlier than the five-minute observation horizon',async()=>{
 const license=await product();const groupId=await group([await person()]);const deadline=new Date(Date.now()+60000).toISOString();
 sourceMode=snapshot=>({...snapshot,memberships:snapshot.memberships.map(member=>({...member,reviewDeadlineAt:deadline}))});await grant(license,groupId);
 assert.equal((await pool.query('SELECT expires_at FROM license_assignments')).rows[0].expires_at.toISOString(),deadline);
 await pool.query("CREATE OR REPLACE FUNCTION license_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+interval '61 seconds'; $$");
 assert.equal(await allocator.count(pool,license.id),0);const read=await api('GET','/groups','manager','license-reader');assert.equal(read.body.groups[0].status,'membership-expired');
});
test('base expiry and overlapping direct or independently observed group sources compose without extending either bound',async()=>{
 const recipient=await person();const license=await product();const first=await group([recipient]);const second=await group([recipient]);const base=new Date(Date.now()+30000).toISOString();
 await grant(license,first,'manager',base);assert.equal((await pool.query('SELECT expires_at FROM license_assignments')).rows[0].expires_at.toISOString(),base);
 await grant(license,second);assert.ok((await pool.query('SELECT expires_at FROM license_assignments')).rows[0].expires_at.getTime()>Date.parse(base));
 await direct(license,recipient);assert.equal((await pool.query('SELECT expires_at FROM license_assignments')).rows[0].expires_at,null);
 await pool.query("CREATE OR REPLACE FUNCTION license_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+interval '301 seconds'; $$");
 assert.equal(await allocator.count(pool,license.id),1);
});
test('group lease audit failure rolls back the observation, member proof and physical projection together',async()=>{
 const license=await product();const groupId=await group([await person()]);await grant(license,groupId);const before=(await pool.query('SELECT * FROM license_group_observations')).rows;const projection=(await pool.query('SELECT * FROM license_assignments')).rows;
 await pool.query("CREATE FUNCTION fail_owned_directory_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Owned directory audit unavailable';END;$$;CREATE TRIGGER fail_owned_directory_audit BEFORE INSERT ON license_group_lease_audit FOR EACH ROW EXECUTE FUNCTION fail_owned_directory_audit()");
 try{await assert.rejects(reconcile(license,groupId),/Owned directory audit/);}finally{await pool.query('DROP TRIGGER fail_owned_directory_audit ON license_group_lease_audit;DROP FUNCTION fail_owned_directory_audit()');}
 assert.deepEqual((await pool.query('SELECT * FROM license_group_observations')).rows,before);assert.deepEqual((await pool.query('SELECT * FROM license_assignments')).rows,projection);
});
test('directory proof expiry after source DML rolls back a positive grant instead of acknowledging it',async()=>{
 const license=await product();const groupId=await group([await person()]);const failing=new LicenseAllocator({query:(...args)=>pool.query(...args),getClient:async()=>{
 const connection=await pool.connect();return{release:()=>connection.release(),query:async(sql,parameters)=>{
 const result=await connection.query(sql,parameters);if(sql.startsWith('INSERT INTO license_audit_events')&&parameters[1]==='group-reconciled')await pool.query("CREATE OR REPLACE FUNCTION license_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+interval '301 seconds'; $$");return result;}};}},{source:client});new GroupLicenseAllocator({allocator:failing,source:client});
 await assert.rejects(failing.assign(license.id,{assignee_type:'group',assignee_id:groupId},'manager',await context()),error=>error.status===409||error.code==='23514'&&error.constraint==='license_group_directory_lease');
 assert.equal((await pool.query('SELECT count(*)::int AS count FROM license_group_observations')).rows[0].count,0);assert.equal((await pool.query('SELECT count(*)::int AS count FROM license_assignments')).rows[0].count,0);
});
for(const[boundary,offset,baseSeconds]of[['directory horizon',301,null],['original business expiry',31,30]])test('deferred SQL fencing catches '+boundary+' expiry only at the actual transaction commit',async()=>{
 const license=await product();const groupId=await group([await person()]);const failing=new LicenseAllocator({query:(...args)=>pool.query(...args),getClient:async()=>{
 const connection=await pool.connect();return{release:()=>connection.release(),query:async(sql,parameters)=>{
 if(sql==='COMMIT')await pool.query(`CREATE OR REPLACE FUNCTION license_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+interval '${offset} seconds'; $$`);return connection.query(sql,parameters);}};}},{source:client});new GroupLicenseAllocator({allocator:failing,source:client});
 await assert.rejects(failing.assign(license.id,{assignee_type:'group',assignee_id:groupId,expires_at:baseSeconds?new Date(Date.now()+baseSeconds*1000).toISOString():undefined},'manager',await context()),error=>error.code==='23514'&&error.message.includes('before commit'));
 assert.equal((await pool.query('SELECT count(*)::int AS count FROM license_group_lease_audit')).rows[0].count,0);
});
test('lease evidence is append-only and raw group sources or unbounded projection writes cannot bypass observation',async()=>{
 const license=await product();const recipient=await person();const groupId=await group([recipient]);await grant(license,groupId);
 for(const table of ['license_group_observations','license_group_member_leases','license_group_lease_audit'])await assert.rejects(pool.query('DELETE FROM '+table),error=>error.code==='42501');
 await assert.rejects(pool.query('UPDATE license_group_member_leases SET valid_until=valid_until+interval \'1 hour\''),error=>error.code==='42501');
 await assert.rejects(pool.query('UPDATE license_assignments SET expires_at=NULL'),error=>['42501','23514'].includes(error.code));
 await assert.rejects(pool.query("INSERT INTO license_assignment_sources(license_id,user_id,source_type,source_id,assigned_by) VALUES($1,$2,'group',$3,'unobserved')",[license.id,await person(),groupId]),error=>error.code==='23514');
});
const administration = new Pool({ connectionString, max: 1 });
const schemas = [`license_groups_${randomUUID().replaceAll('-', '')}`, `identity_groups_${randomUUID().replaceAll('-', '')}`];
let pool; let directory; let allocator; let groups; let client; let server; let privateKey; let policyServer; let policyDatabase; let policyBase; let adapter; let gateway; let Gateway;
let sourceMode = null;
let bindingMode = null;
let userMode = null;
const issuer = 'https://group-integration.test';
const policyMigration = file => fs.readFileSync(path.join(__dirname, '../../db/migrations', file), 'utf8');

before(async () => {
  for (const schema of schemas) await administration.query(`CREATE SCHEMA ${schema}`);
  pool = new Pool({ connectionString, max: 12, options: `-c search_path=${schemas[0]},public` });
  directory = new Pool({ connectionString, max: 8, options: `-c search_path=${schemas[1]},public` });
  for (const migration of fs.readdirSync(path.join(__dirname,'../../db/migrations')).filter(name=>/^(00[4-9]|01[0-7]|02[0-2])_.*\.sql$/.test(name)).sort()) await pool.query(policyMigration(migration));
  for (const migration of fs.readdirSync(path.join(__dirname,'../../../../identity-service/migrations')).filter(file=>file.endsWith('.sql')).sort()) await directory.query(fs.readFileSync(path.join(__dirname, '../../../../identity-service/migrations', migration), 'utf8'));
  await require('../../../../../../scripts/lib/tenant-ownership-fixture.cjs').installTenantFixture(directory,schemas[1]);
  const keys = await generateKeyPair('RS256'); privateKey = keys.privateKey;
  const store = new GroupSnapshotStore({ transaction: async (operation) => {
    const connection = await directory.connect();
    try { await connection.query('BEGIN'); const result = await operation(connection); await connection.query('COMMIT'); return result; }
    catch (error) { await connection.query('ROLLBACK'); throw error; }
    finally { connection.release(); }
  } });
  const app = express();
  const userStore = new UserSnapshotStore(store.database);
  const publicKey = { ...await exportJWK(keys.publicKey), kid: 'group-tests', alg: 'RS256', use: 'sig' };
  app.get('/jwks', (_request, response) => response.json({ keys: [publicKey] }));
  app.get('/oauth/access-state', async (request, response) => {
    try {
      const { payload } = await jwtVerify(request.headers.authorization.slice(7), keys.publicKey, { issuer, audience: 'opendirectory-api' });
      response.json({ schemaVersion: 1, active: true, issuer: payload.iss, subject: payload.sub, tokenId: payload.jti, expiresAt: payload.exp });
    } catch { response.status(401).json({ error: 'invalid_token' }); }
  });
  app.use(async (request, response, next) => {
    try { request.user = (await jwtVerify(request.headers.authorization?.slice(7), keys.publicKey, { issuer, audience: 'opendirectory-api' })).payload; if (request.user.token_use !== 'access') throw new Error('Invalid token purpose'); next(); }
    catch { response.status(401).json({ error: 'invalid token' }); }
  });
  app.use('/api', requireIdentityAccess);
  app.get('/api/identity/device-inventory', (_request, response) => response.status(403).json({ error: 'inventory_source_not_supported_by_fixture' }));
  app.get('/api/license-users/:id/snapshot', async (request, response) => {
    if (sourceMode === 'offline') return response.status(503).json({ error: 'source offline' });
    if (typeof userMode === 'number') return response.status(userMode).json({ error: 'eligibility unavailable' });
    try {
      const snapshot = await userStore.snapshot(request.params.id, { issuer: request.user.iss, subject: request.user.sub }, request.identityPermissions.includes('licenses.users.read'));
      response.set('X-OD-License-Snapshot-Protocol', '1').json(typeof userMode === 'function' ? userMode(snapshot) : snapshot);
    }
    catch (error) { response.status(error.status || 503).json({ error: error.message }); }
  });
  app.get('/api/identity/subject', async (request, response) => {
    if (bindingMode === 'offline') return response.status(503).json({ error: 'identity source offline' });
    try {
      const result = await store.subject({ issuer: request.user.iss, subject: request.user.sub });
      response.json(typeof bindingMode === 'function' ? bindingMode(result) : result);
    }
    catch (error) { response.status(error.status || 503).json({ error: error.message }); }
  });
  app.get('/api/license-groups/:id/snapshot', async (request, response) => {
    if (sourceMode === 'offline'||sourceMode==='group-offline') return response.status(503).json({ error: 'source offline' });
    try {
      const snapshot = await store.snapshot(request.params.id, { issuer: request.user.iss, subject: request.user.sub });
      response.set('X-OD-License-Snapshot-Protocol', '1').json(typeof sourceMode === 'function' ? sourceMode(snapshot) : snapshot);
    } catch (error) { response.status(error.status || 503).json({ error: error.message }); }
  });
  server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  client = new GroupSnapshotClient({ baseUrl: `http://127.0.0.1:${server.address().port}` });
  allocator = new LicenseAllocator({ query: (sql, parameters) => pool.query(sql, parameters), getClient: () => pool.connect() }, { source: client });
  groups = new GroupLicenseAllocator({ allocator, source: client });
  const policyUrl = new URL(connectionString);
  policyUrl.searchParams.set('options', `-c search_path=${schemas[0]},public`);
  process.env.DATABASE_URL = policyUrl.toString();
  process.env.OIDC_ISSUER = issuer;
  process.env.JWKS_URI = `http://127.0.0.1:${server.address().port}/jwks`;
  process.env.OIDC_ACCESS_STATE_URL = `http://127.0.0.1:${server.address().port}/oauth/access-state`;
  process.env.IDENTITY_SERVICE_URL = `http://127.0.0.1:${server.address().port}`;
  process.env.LICENSE_DEMO_MODE = 'false';
  process.env.LOG_LEVEL = 'error';
  policyDatabase = require('../../db/postgres');
  policyServer = require('../../index').listen(0, '127.0.0.1');
  await new Promise(resolve => policyServer.once('listening', resolve));
  policyBase = `http://127.0.0.1:${policyServer.address().port}`;
  const { createService } = require('../../../../license-management/src');
  const { PolicyLicenseClient } = require('../../../../license-management/src/PolicyLicenseClient');
  adapter = createService({ client: new PolicyLicenseClient({ baseUrl: policyBase }) });
  await new Promise(resolve => adapter.server.listen(0, '127.0.0.1', resolve));
  process.env.POLICY_SERVICE_URL = policyBase;
  process.env.LICENSE_ADAPTER_URL = `http://127.0.0.1:${adapter.server.address().port}`;
  Gateway = require('../../../../api-gateway/src');
  await Gateway.databaseReady;
  gateway = new Gateway({ discover: false, enabledModules: ['policy-service', 'identity-service', 'license-management', 'device-management'] });
  await new Promise(resolve => gateway.server.listen(0, '127.0.0.1', resolve));
});

beforeEach(async () => {
  await pool.query('CREATE OR REPLACE FUNCTION license_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp(); $$');
  process.env.GATEWAY_WEBHOOK_ALLOWED_ORIGINS = '';
  sourceMode = null;
  bindingMode = null;
  userMode = null;
  await pool.query('TRUNCATE api_keys,webhooks,webhook_deliveries CASCADE');
  await pool.query('TRUNCATE license_grants,license_assignments,license_requests,license_catalog,license_subjects,license_audit_events,license_assignment_sources,license_group_rules CASCADE');
  await directory.query('TRUNCATE users,groups,group_members,identity_deleted_groups,identity_group_audit,identity_group_outbox,identity_subject_links,identity_link_audit,identity_user_audit,identity_user_outbox,identity_deleted_users CASCADE');
  for (const subject of ['manager', 'requester', 'independent-reviewer']) await link(subject, await person());
});

after(async () => {
  if (gateway) { gateway.stop(); gateway.server.closeAllConnections(); }
  if (Gateway) await Gateway.closeDatabase();
  if (adapter) { adapter.server.closeAllConnections(); await new Promise(resolve => adapter.server.close(resolve)); }
  if (policyServer) { policyServer.closeAllConnections(); await new Promise(resolve => policyServer.close(resolve)); }
  if (policyDatabase) await policyDatabase.shutdown();
  if (server) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
  if (pool) await pool.end(); if (directory) await directory.end();
  for (const schema of schemas) await administration.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
  await administration.end();
});

async function token(actor, role = 'user', claims = {}) {
  return `Bearer ${await new SignJWT({ sub: actor, jti: randomUUID(), roles: [role], token_use: 'access', ...claims }).setProtectedHeader({ alg: 'RS256', kid: 'group-tests' }).setIssuer(issuer).setAudience('opendirectory-api').setIssuedAt().setExpirationTime('5m').sign(privateKey)}`;
}
async function context(actor = 'manager', role = 'license-manager') {
  const authorization = await token(actor, role);
  return { authorization, principal: await client.subject(authorization, { issuer, subject: actor }) };
}
async function person() { const id = randomUUID(); await directory.query('INSERT INTO users(id,username,email) VALUES($1::uuid,$1::text,$2)', [id, `${id}@test.invalid`]); return id; }
async function group(members = []) {
  const id = randomUUID(); await directory.query('INSERT INTO groups(id,name) VALUES($1,$2)', [id, 'Engineering']);
  for (const member of members) await directory.query('INSERT INTO group_members(group_id,user_id) VALUES($1,$2)', [id, member]);
  return id;
}
async function product(seats = 5, autoApprove = false) { return (await pool.query('INSERT INTO license_catalog(name,total_seats,auto_approve) VALUES($1,$2,$3) RETURNING *', ['Office', seats, autoApprove])).rows[0]; }
async function grant(license, groupId, actor = 'manager', expiresAt) { const authentication = await context(actor); return allocator.assign(license.id, { assignee_type: 'group', assignee_id: groupId, expires_at: expiresAt }, authentication.principal.userId || actor, authentication); }
async function direct(license, userId, expiresAt) { return allocator.assign(license.id, { assignee_type: 'user', assignee_id: userId, expires_at: expiresAt }, 'manager', await context()); }
async function assigned(license) { return (await pool.query("SELECT assignee_id FROM license_assignments WHERE license_id=$1 AND (expires_at IS NULL OR expires_at>clock_timestamp()) ORDER BY assignee_id", [license.id])).rows.map(row => row.assignee_id); }
async function reconcile(license, groupId) { return groups.reconcile(license.id, groupId, 'manager', await context()); }
async function requestLicense(licenseId, request, authentication) {
  const verified = authentication || await context('requester');
  return allocator.request(licenseId, { ...request, requester_id: verified.principal.userId }, verified);
}
async function reviewLicense(requestId, actor, decision, authentication) {
  const verified = authentication || await context(actor, 'license-approver');
  return allocator.review(requestId, verified.principal.userId || actor, decision, verified);
}
async function link(subject, userId) { await directory.query('INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES($1,$2,$3)', [issuer, subject, userId]); }
async function api(method, route, actor, role = 'user', body, claims = {}, headers = {}) {
  const response = await fetch(`${policyBase}/api/licenses${route}`, { method, signal: AbortSignal.timeout(10000), headers: { Authorization: await token(actor, role, claims), 'Content-Type': 'application/json', ...headers },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  return { status: response.status, body: response.status === 204 ? null : await response.json(), headers: response.headers };
}

async function grantActor(actor = 'manager') {
  const authentication = await context(actor);
  const userId = authentication.principal.userId;
  const authTime = Math.floor(Date.now() / 1000);
  return { actor_type: 'user', identity_authorization: { userId, revision: '1', linkRevision: '1', rolesRevision: 'a'.repeat(64) },
    auth_time: authTime, amr: ['pwd', 'otp'], mfa_authorization: { schemaVersion: 1, userId, revision: '1', authTime, methods: ['pwd', 'otp'] } };
}

async function grantRecord(licenseId, grantId) {
  const result = await api('GET', `/${licenseId}/grants/${grantId}`, 'manager', 'license-reader');
  assert.equal(result.status, 200);
  return result;
}

async function withdraw(licenseId, record, claims, body = { confirm: true, reason: 'Individually reviewed license source withdrawal' }) {
  return api('POST', `/${licenseId}/grants/${record.body.id}/revoke`, 'manager', 'license-manager', body, claims || await grantActor(), { 'If-Match': record.headers.get('etag') });
}

test('grant lineage survives no-op reconciliation and migration reapplication, but fences local membership changes', async () => {
  const license = await product(); const first = await person(); const groupId = await group([first]);
  const configured = await grant(license, groupId);
  const initial = await grantRecord(license.id, configured.rule.grant_id);
  assert.equal(initial.body.kind, 'group'); assert.equal(initial.body.origin, 'allocated'); assert.equal(initial.body.sourceUsers, 1);
  await reconcile(license, groupId);
  assert.equal((await grantRecord(license.id, configured.rule.grant_id)).headers.get('etag'), initial.headers.get('etag'));
  await pool.query(policyMigration('010_license_grant_lineage.sql'));
  assert.deepEqual((await grantRecord(license.id, configured.rule.grant_id)).body, initial.body);
  const second = await person(); await directory.query('INSERT INTO group_members(group_id,user_id) VALUES($1,$2)', [groupId, second]);
  await reconcile(license, groupId);
  const changed = await grantRecord(license.id, configured.rule.grant_id);
  assert.equal(changed.body.id, initial.body.id); assert.ok(BigInt(changed.body.version) > BigInt(initial.body.version));
  assert.equal((await withdraw(license.id, initial)).status, 412);
  assert.deepEqual(new Set(await assigned(license)), new Set([first, second]));
});

test('a confirmed group grant withdrawal preserves direct and other-group sources, without automatic resurrection', async () => {
  const license = await product(); const first = await person(); const second = await person();
  const groupId = await group([first, second]); const other = await group([second]);
  const configured = await grant(license, groupId); await grant(license, other); await direct(license, first);
  const before = await grantRecord(license.id, configured.rule.grant_id);
  const result = await withdraw(license.id, before);
  assert.equal(result.status, 200); assert.equal(result.body.localOnly, true); assert.equal(result.body.sourcesRemoved, 2);
  assert.equal(result.body.usersRetainingAssignment, 2); assert.equal(result.body.grant.state, 'revoked');
  await reconcile(license, groupId); assert.equal((await grantRecord(license.id, configured.rule.grant_id)).body.state, 'revoked');
  assert.equal((await pool.query('SELECT COUNT(*)::int AS count FROM license_assignment_sources WHERE grant_id=$1', [configured.rule.grant_id])).rows[0].count, 0);
  const regranted = await grant(license, groupId); assert.notEqual(regranted.rule.grant_id, configured.rule.grant_id);
  assert.equal((await withdraw(license.id, before)).status, 412);
  assert.equal((await grantRecord(license.id, regranted.rule.grant_id)).body.state, 'active');
  const evidence = (await pool.query("SELECT * FROM license_grant_events WHERE grant_id=$1 ORDER BY version DESC LIMIT 1", [configured.rule.grant_id])).rows[0];
  assert.equal(evidence.actor_subject, 'manager'); assert.equal(evidence.actor_issuer, issuer);
  assert.equal(evidence.actor_user_id, (await context()).principal.userId);
});

test('direct grant reincarnations cannot be retargeted by an earlier source form', async () => {
  const license = await product(); const userId = await person(); await direct(license, userId);
  const id = (await pool.query("SELECT grant_id FROM license_assignment_sources WHERE source_type='direct'")).rows[0].grant_id;
  const record = await grantRecord(license.id, id);
  assert.equal((await withdraw(license.id, record)).status, 200); assert.deepEqual(await assigned(license), []);
  await direct(license, userId);
  const next = (await pool.query("SELECT grant_id FROM license_assignment_sources WHERE source_type='direct'")).rows[0].grant_id;
  assert.notEqual(next, id); assert.equal((await withdraw(license.id, record)).status, 412);
  assert.equal((await withdraw(license.id, await grantRecord(license.id, id))).status, 409);
  assert.deepEqual(await assigned(license), [userId]);
});

test('grant history and source provenance cannot be rewritten or caller-chosen', async () => {
  const license = await product(); const userId = await person(); await direct(license, userId);
  const queries = [
    ['UPDATE license_grants SET recipient_id=$1', [randomUUID()]],
    ['DELETE FROM license_grant_events', []], ['DELETE FROM license_grants', []],
    ["UPDATE license_grant_events SET state='revoked'", []],
    ['UPDATE license_assignment_sources SET user_id=$1', [randomUUID()]],
    ['UPDATE license_assignment_sources SET grant_id=$1', [randomUUID()]],
    ["UPDATE license_assignment_sources SET assigned_by='someone-else'", []],
    ["INSERT INTO license_assignment_sources(license_id,user_id,source_type,source_id,assigned_by,grant_id) VALUES($1,$2,'direct','direct','manager',$3)", [license.id, randomUUID(), randomUUID()]],
    ["SELECT license_grant_event($1,'revoked','forged',NULL)", [(await pool.query('SELECT id FROM license_grants WHERE license_id=$1', [license.id])).rows[0].id]],
  ];
  for (const [sql, parameters] of queries) await assert.rejects(pool.query(sql, parameters), error => error.code === '42501');
  assert.deepEqual(await assigned(license), [userId]);
});

test('grant reads and destructive writes retain separate least-privilege permissions and strict scopes', async () => {
  const license = await product(); const configured = await grant(license, await group([])); const route = `/${license.id}/grants/${configured.rule.grant_id}`;
  for (const role of ['user', 'license-approver', 'license-fulfillment-reader', 'access-reviewer']) assert.equal((await api('GET', route, 'manager', role)).status, 403);
  assert.equal((await api('POST', route + '/revoke', 'manager', 'license-reader', { confirm: true, reason: 'A reviewed withdrawal' })).status, 403);
  assert.equal((await api('GET', `/${randomUUID()}/grants/${configured.rule.grant_id}`, 'manager', 'license-reader')).status, 404);
  for (const suffix of ['?unknown=1', '?after=not-a-uuid', `?after=${randomUUID()}&after=${randomUUID()}`]) assert.equal((await api('GET', `/${license.id}/grants${suffix}`, 'manager', 'license-reader')).status, 400);
  const list = await api('GET', `/${license.id}/grants`, 'manager', 'license-reader');
  assert.equal(list.headers.get('cache-control'), 'no-store'); assert.equal(list.body.grants.length, 1); assert.equal(list.body.nextAfter, null);
});

test('source withdrawal requires bound fresh MFA, an exact version and an explicit reason', async () => {
  const license = await product(); const configured = await grant(license, await group([])); const record = await grantRecord(license.id, configured.rule.grant_id);
  const claims = await grantActor();
  for (const invalid of [{ ...claims, amr: ['pwd'] }, { ...claims, actor_type: 'service' }, { ...claims, auth_time: claims.auth_time - 301, mfa_authorization: { ...claims.mfa_authorization, authTime: claims.auth_time - 301 } },
    { ...claims, mfa_authorization: { ...claims.mfa_authorization, userId: randomUUID() } }]) assert.ok([403, 428].includes((await withdraw(license.id, record, invalid)).status));
  const route = `/${license.id}/grants/${configured.rule.grant_id}/revoke`;
  assert.equal((await api('POST', route, 'manager', 'license-manager', { confirm: true, reason: 'Reviewed withdrawal' }, claims)).status, 428);
  for (const invalid of [{ confirm: false, reason: 'Reviewed withdrawal' }, { confirm: true, reason: 'short' }, { confirm: true, reason: 'Reviewed withdrawal', actor: 'forged' }]) assert.equal((await withdraw(license.id, record, claims, invalid)).status, 400);
  assert.equal((await grantRecord(license.id, configured.rule.grant_id)).body.state, 'active');
});

test('grant inventory uses bounded keyset pages without leaking another pool or silently dropping the continuation', async () => {
  const license = await product(); const other = await product();
  await pool.query("INSERT INTO license_group_rules(license_id,group_id,configured_by) SELECT $1,gen_random_uuid()::text,'owned-pagination-fixture' FROM generate_series(1,101)", [license.id]);
  await pool.query("INSERT INTO license_group_rules(license_id,group_id,configured_by) VALUES($1,$2,'owned-other-pool')", [other.id, randomUUID()]);
  const first = await api('GET', `/${license.id}/grants`, 'manager', 'license-reader');
  assert.equal(first.status, 200); assert.equal(first.body.grants.length, 100); assert.equal(first.body.hasMore, true); assert.equal(first.body.nextAfter, first.body.grants[99].id);
  const second = await api('GET', `/${license.id}/grants?after=${first.body.nextAfter}`, 'manager', 'license-reader');
  assert.equal(second.status, 200); assert.equal(second.body.grants.length, 1); assert.equal(second.body.hasMore, false); assert.equal(second.body.nextAfter, null);
  const combined = [...first.body.grants, ...second.body.grants]; assert.equal(new Set(combined.map(row => row.id)).size, 101);
  assert.ok(combined.every(row => row.licenseId === license.id));
});

test('two concurrent source withdrawal forms produce exactly one committed receipt', async () => {
  const license = await product(); const configured = await grant(license, await group([await person()])); const record = await grantRecord(license.id, configured.rule.grant_id);
  const results = await Promise.all([withdraw(license.id, record), withdraw(license.id, record)]);
  assert.deepEqual(results.map(result => result.status).sort(), [200, 412]);
  assert.equal((await pool.query("SELECT COUNT(*)::int AS count FROM license_audit_events WHERE action='grant-revoked'")).rows[0].count, 1);
  assert.deepEqual(await assigned(license), []);
});

test('a group membership committed while withdrawal waits for the pool lock invalidates the captured intent', async () => {
  const license = await product(); const groupId = await group([await person()]); const configured = await grant(license, groupId);
  const record = await grantRecord(license.id, configured.rule.grant_id); const newcomer = await person();
  const owner = await pool.connect(); let pending;
  try {
    await owner.query('BEGIN'); await owner.query('SELECT id FROM license_catalog WHERE id=$1 FOR UPDATE', [license.id]);
    pending = withdraw(license.id, record);
    let waiting = false;
    for (let attempt = 0; attempt < 100; attempt++) {
      waiting = (await pool.query("SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'SELECT * FROM license_catalog WHERE id = %'")).rows.length > 0;
      if (waiting) break;
      await new Promise(resolve => setTimeout(resolve, 20));
    }
    assert.equal(waiting, true);
    await directory.query('INSERT INTO group_members(group_id,user_id) VALUES($1,$2)',[groupId,newcomer]);
    const authentication=await context();const snapshot=await groups.snapshot(groupId,authentication);
    await owner.query('INSERT INTO license_subjects(user_id,directory_revision,directory_enabled,directory_deleted) VALUES($1,$2,true,false)',[newcomer,snapshot.memberships.find(member=>member.userId===newcomer).eligibilityRevision]);
    await groups.apply(owner,license,snapshot,'owned-racing-allocator',new Set());
    await owner.query('COMMIT'); assert.equal((await pending).status, 412);
    assert.equal((await grantRecord(license.id, configured.rule.grant_id)).body.state, 'active'); assert.equal((await assigned(license)).length, 2);
  } finally { await owner.query('ROLLBACK'); owner.release(); if (pending) await pending; }
});

test('audit failure rolls back the source, group state, seat counter and lineage together', async () => {
  const license = await product(); const member = await person(); const configured = await grant(license, await group([member])); const record = await grantRecord(license.id, configured.rule.grant_id);
  await pool.query("CREATE FUNCTION reject_grant_audit() RETURNS trigger AS $$ BEGIN IF NEW.action='grant-revoked' THEN RAISE EXCEPTION 'Owned audit failure'; END IF; RETURN NEW; END $$ LANGUAGE plpgsql; CREATE TRIGGER reject_grant_audit BEFORE INSERT ON license_audit_events FOR EACH ROW EXECUTE FUNCTION reject_grant_audit()");
  try { assert.equal((await withdraw(license.id, record)).status, 503); }
  finally { await pool.query('DROP TRIGGER reject_grant_audit ON license_audit_events; DROP FUNCTION reject_grant_audit()'); }
  assert.deepEqual((await grantRecord(license.id, configured.rule.grant_id)).body, record.body);
  assert.deepEqual(await assigned(license), [member]); assert.equal((await pool.query('SELECT used_seats FROM license_catalog WHERE id=$1', [license.id])).rows[0].used_seats, 1);
});

async function legacy(method, route, actor, role = 'user', body, claims = {}) {
  const response = await fetch(`http://127.0.0.1:${adapter.server.address().port}/api/license${route}`, { method, signal: AbortSignal.timeout(10000),
    headers: { Authorization: await token(actor, role, claims), 'Content-Type': 'application/json', 'X-User-Roles': 'admin', 'X-Service-Token': 'forged' },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  return { status: response.status, body: response.status === 204 ? null : await response.json() };
}

async function viaGateway(method, path, actor = 'manager', role = 'license-manager', body, claims = {}) {
  const response = await fetch(`http://127.0.0.1:${gateway.server.address().port}${path}`, { method, signal: AbortSignal.timeout(10000),
    headers: { Authorization: await token(actor, role, claims), 'Content-Type': 'application/json' }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  return { status: response.status, body: response.status === 204 ? null : await response.json() };
}

test('overlapping groups consume one seat per user, not one per group or source', async () => {
  const users = await Promise.all([person(), person(), person()]); const license = await product(3);
  await grant(license, await group(users.slice(0, 2)));
  await grant(license, await group(users.slice(1)));
  assert.deepEqual(await assigned(license), users.sort());
  assert.equal((await pool.query('SELECT COUNT(*)::int AS count FROM license_assignment_sources')).rows[0].count, 4);
  assert.equal((await pool.query('SELECT used_seats FROM license_catalog WHERE id=$1', [license.id])).rows[0].used_seats, 3);
});

test('real signed self-service resolves the canonical identity, ignores forged ownership, and preserves issuer provenance', async () => {
  const userId = await person(); await link('alice-alias', userId); const license = await product(2, true);
  const result = await api('POST', `/${license.id}/request`, 'alice-alias', 'user', { requester_id: randomUUID(), directory_user_id: randomUUID(), requester_name: 'forged' }, { directory_user_id: randomUUID() });
  assert.equal(result.status, 201); assert.equal(result.body.requester_id, userId); assert.equal(result.body.assignee_id, userId);
  assert.equal(result.body.identity_bound, true); assert.equal(result.body.requester_issuer, issuer); assert.equal(result.body.requester_subject, 'alice-alias');
  assert.equal(result.body.requester_name, userId);
  const audit = (await pool.query("SELECT actor,actor_issuer,actor_subject FROM license_audit_events WHERE action='auto-approved'")).rows[0];
  assert.deepEqual(audit, { actor: userId, actor_issuer: issuer, actor_subject: 'alice-alias' });
  await grant(license, await group([userId]));
  assert.deepEqual(await assigned(license), [userId]);
  const retry = await api('POST', `/${license.id}/request`, 'alice-alias', 'user', {});
  assert.equal(retry.status, 200); assert.equal(retry.body.id, result.body.id);
});

test('canonical beneficiaries cannot approve or deny delegated direct requests through JWT aliases', async () => {
  const userId = await person(); await link('beneficiary-alias', userId); const license = await product();
  const created = await api('POST', `/${license.id}/request`, 'manager', 'license-manager', { assignee_type: 'user', assignee_id: userId });
  assert.equal(created.status, 201);
  for (const decision of ['approve', 'deny']) {
    const result = await api('POST', `/requests/${created.body.id}/${decision}`, 'beneficiary-alias', 'license-approver', { decided_by: 'independent-reviewer' });
    assert.equal(result.status, 403);
  }
  assert.equal((await pool.query('SELECT status FROM license_requests')).rows[0].status, 'pending');
  assert.deepEqual(await assigned(license), []);
});

test('relinked subject aliases retain canonical ownership and cannot review their earlier requests', async () => {
  const userId = await person(); await link('first-alias', userId); const license = await product();
  const created = await api('POST', `/${license.id}/request`, 'first-alias', 'user', {});
  assert.equal(created.status, 201);
  await directory.query('DELETE FROM identity_subject_links WHERE issuer=$1 AND subject=$2', [issuer, 'first-alias']);
  await link('second-alias', userId);
  const history = await api('GET', '/requests?requester_id=manager', 'second-alias');
  assert.deepEqual(history.body.requests.map(request => request.id), [created.body.id]);
  for (const action of ['approve', 'deny']) assert.equal((await api('POST', `/requests/${created.body.id}/${action}`, 'second-alias', 'admin', {})).status, 403);
  assert.equal((await api('GET', '/requests', 'first-alias')).status, 403);
});

test('an independent canonical reviewer is recorded with signed provenance, never body-supplied claims', async () => {
  const userId = await person(); await link('requester-alias', userId); const license = await product();
  const created = await api('POST', `/${license.id}/request`, 'requester-alias', 'user', {});
  const reviewer = (await context('independent-reviewer')).principal.userId;
  const result = await api('POST', `/requests/${created.body.id}/approve`, 'independent-reviewer', 'license-approver', { decided_by: userId, issuer: 'forged' });
  assert.equal(result.status, 200); assert.equal(result.body.decided_by, reviewer);
  const audit = (await pool.query("SELECT actor,actor_issuer,actor_subject FROM license_audit_events WHERE action='approved'")).rows[0];
  assert.deepEqual(audit, { actor: reviewer, actor_issuer: issuer, actor_subject: 'independent-reviewer' });
  assert.deepEqual(await assigned(license), [userId]);
});

test('unlinked subjects cannot impersonate canonical UUIDs or self-service through scope, token or body claims', async () => {
  const userId = await person(); const license = await product(1, true);
  const claims = { directory_user_id: userId, permissions: ['licenses.catalog.manage'], scope: 'identity.admin' };
  const capabilities = await api('GET', '/access', userId, 'admin', undefined, claims);
  assert.equal(capabilities.status, 200); assert.equal(capabilities.body.identityState, 'unlinked'); assert.deepEqual(capabilities.body.permissions, []); assert.equal(capabilities.body.subject, null);
  for (const route of [`/${license.id}/request`, `/${license.id}/assign`, '/']) assert.equal((await api('POST', route, userId, 'admin', { requester_id: userId, assignee_type: 'user', assignee_id: userId }, claims)).status, 403);
  assert.equal((await api('GET', '/kiosk', userId)).status, 200);
  assert.deepEqual(await assigned(license), []);
});

test('directory disablement blocks a still-valid privileged token before license mutation', async () => {
  const license = await product(); const manager = (await context()).principal.userId;
  await directory.query('UPDATE users SET enabled=false WHERE id=$1', [manager]);
  assert.equal((await api('GET', '/access', 'manager', 'admin')).body.identityState, 'disabled');
  assert.equal((await api('POST', `/${license.id}/request`, 'manager', 'admin', {})).status, 403);
  assert.equal((await api('GET', '/requests', 'manager', 'admin')).status, 403);
});

test('unavailable or mismatched identity sources cannot fall back to token identifiers', async () => {
  const license = await product(1, true);
  for (const mode of ['offline', value => ({ ...value, subject: 'forged' }), value => ({ ...value, issuer: 'https://untrusted.test' })]) {
    bindingMode = mode;
    const access = await api('GET', '/access', 'manager', 'admin');
    assert.equal(access.status, 200); assert.equal(access.body.identityState, 'unavailable'); assert.deepEqual(access.body.permissions, []);
    assert.equal((await api('POST', `/${license.id}/request`, 'manager', 'admin', {})).status, 503);
  }
  assert.deepEqual(await assigned(license), []);
});

test('legacy request provenance is not guessed, leaked through ownership, reused, or approved', async () => {
  const license = await product(); const manager = (await context()).principal.userId;
  const historical = (await pool.query("INSERT INTO license_requests(license_id,license_name,requester_id,assignee_type,assignee_id) VALUES($1,'Office',$2,'user',$2) RETURNING *", [license.id, manager])).rows[0];
  assert.equal(historical.identity_bound, false);
  assert.deepEqual((await api('GET', '/requests', 'manager')).body.requests, []);
  const queue = await api('GET', '/requests', 'independent-reviewer', 'license-approver');
  assert.equal(queue.body.requests.length, 1); assert.equal(queue.body.requests[0].identity_bound, false);
  for (const action of ['approve', 'deny']) assert.equal((await api('POST', `/requests/${historical.id}/${action}`, 'independent-reviewer', 'license-approver', {})).status, 409);
  const fresh = await api('POST', `/${license.id}/request`, 'manager', 'user', {});
  assert.equal(fresh.status, 201); assert.notEqual(fresh.body.id, historical.id); assert.equal(fresh.body.identity_bound, true);
  await pool.query(policyMigration('007_license_principal_binding.sql'));
  assert.equal((await pool.query('SELECT identity_bound FROM license_requests WHERE id=$1', [historical.id])).rows[0].identity_bound, false);
});

test('local offboarding uses canonical ownership across alias changes and reactivation never restores requests', async () => {
  const userId = await person(); await link('leaver', userId); const license = await product();
  const created = await api('POST', `/${license.id}/request`, 'leaver', 'user', {});
  assert.equal(created.status, 201);
  await directory.query('DELETE FROM identity_subject_links WHERE issuer=$1 AND subject=$2', [issuer, 'leaver']); await link('leaver-alias', userId);
  const offboarded = await api('POST', `/users/${userId}/offboard`, 'manager', 'admin', {});
  assert.equal(offboarded.status, 200); assert.equal(offboarded.body.requestsCancelled, 1);
  assert.equal((await api('POST', `/${license.id}/request`, 'leaver-alias', 'user', {})).status, 403);
  assert.equal((await api('POST', `/users/${userId}/activate`, 'manager', 'admin', {})).status, 200);
  assert.equal((await pool.query('SELECT status FROM license_requests WHERE id=$1', [created.body.id])).rows[0].status, 'cancelled');
});

test('user-targeting public mutations require canonical directory UUIDs', async () => {
  const license = await product();
  for (const route of [`/${license.id}/request`, `/${license.id}/assign`]) assert.equal((await api('POST', route, 'manager', 'license-manager', { assignee_type: 'user', assignee_id: 'oidc-alias' })).status, 400);
  for (const action of ['offboard', 'activate']) assert.equal((await api('POST', `/users/oidc-alias/${action}`, 'manager', 'admin', {})).status, 400);
});

test('parallel requests retain separate canonical audit principals', async () => {
  const first = await person(); const second = await person(); await link('first', first); await link('second', second); const license = await product(2, true);
  const results = await Promise.all(['first', 'second'].map(actor => api('POST', `/${license.id}/request`, actor, 'user', {})));
  assert.deepEqual(results.map(result => result.status), [201, 201]);
  const audit = (await pool.query("SELECT actor,actor_subject FROM license_audit_events WHERE action='auto-approved' ORDER BY actor_subject")).rows;
  assert.deepEqual(audit, [{ actor: first, actor_subject: 'first' }, { actor: second, actor_subject: 'second' }]);
});

test('the real gateway accepts signed API-audience tokens and forwards the same operator through both license paths', async () => {
  const userId = await person(); const license = await product(1);
  const assigned = await viaGateway('POST', `/api/licenses/${license.id}/assign`, 'manager', 'license-manager', { assignee_type: 'user', assignee_id: userId });
  assert.equal(assigned.status, 201); assert.equal(assigned.body.assigned_by, (await context()).principal.userId);
  const detail = await viaGateway('GET', `/api/license/licenses/${license.id}`);
  assert.equal(detail.status, 200); assert.equal(detail.body.used_seats, 1);
  assert.equal((await viaGateway('POST', `/api/licenses/${license.id}/assign`, 'requester', 'user', { assignee_type: 'user', assignee_id: userId }, { scope: 'licenses.assignments.manage' })).status, 403);
});

test('gateway control-plane grants cannot be obtained from scope/body fields or retired keys', async () => {
  const denied = await viaGateway('POST', '/api/gateway/api-keys', 'requester', 'user', { name: 'Root', permissions: ['*'], roles: ['admin'] });
  assert.equal(denied.status, 403);
  assert.equal((await viaGateway('POST', '/api/gateway/api-keys', 'manager', 'gateway-key-administrator', { name: 'Root' })).status, 410);
  assert.equal((await pool.query('SELECT COUNT(*)::int AS count FROM api_keys')).rows[0].count, 0);
  const inventorySource = await viaGateway('GET', '/api/identity/device-inventory', 'manager', 'gateway-administrator');
  assert.equal(inventorySource.status, 403);
  assert.equal(inventorySource.body.error, 'inventory_source_not_supported_by_fixture');
  const inventory = await viaGateway('GET', '/api/devices', 'manager', 'gateway-administrator');
  assert.equal(inventory.status, 403);
  assert.equal(inventory.body.error, 'Canonical inventory human required');
});

test('authorized webhook metadata is durable, secrets are rejected, and delivery defaults to deny without egress approval', async () => {
  assert.equal((await viaGateway('POST', '/api/gateway/webhooks', 'requester', 'user', { name: 'Bad', url: 'https://example.test' })).status, 403);
  assert.equal((await viaGateway('POST', '/api/gateway/webhooks', 'manager', 'gateway-webhook-administrator', { name: 'Bad', url: 'https://example.test', secret: 'unimplemented' })).status, 422);
  const created = await viaGateway('POST', '/api/gateway/webhooks', 'manager', 'gateway-webhook-administrator', { name: 'Approved metadata', url: 'https://example.test/hooks', events: ['test'] });
  assert.equal(created.status, 201); assert.equal(created.body.secret_hash, undefined);
  const rows = await viaGateway('GET', '/api/gateway/webhooks', 'manager', 'gateway-reader');
  assert.equal(rows.status, 200); assert.equal(rows.body.length, 1); assert.equal(rows.body[0].id, created.body.id);
  assert.equal((await viaGateway('POST', `/api/gateway/webhooks/${created.body.id}/test`, 'manager', 'gateway-webhook-administrator', {})).status, 403);
  assert.equal((await pool.query('SELECT COUNT(*)::int AS count FROM webhook_deliveries')).rows[0].count, 0);
  assert.equal((await viaGateway('DELETE', `/api/gateway/webhooks/${created.body.id}`, 'manager', 'gateway-webhook-administrator')).status, 204);
});

test('approved unsigned webhook tests persist actual delivery IDs and failure counts without following redirects', async () => {
  const created = await viaGateway('POST', '/api/gateway/webhooks', 'manager', 'gateway-webhook-administrator', { name: 'Delivery contract', url: 'https://example.test/hooks', events: ['test'] });
  assert.equal(created.status, 201);
  process.env.GATEWAY_WEBHOOK_ALLOWED_ORIGINS = 'https://example.test';
  const originalFetch = global.fetch;
  let attempts = 0;
  global.fetch = async (url, options) => {
    if (String(url) !== 'https://example.test/hooks') return originalFetch(url, options);
    attempts++;
    assert.equal(options.redirect, 'error');
    assert.equal(options.headers['X-OpenDirectory-Delivery'], 'unsigned-test');
    assert.equal(options.headers.Authorization, undefined);
    assert.equal(options.headers['X-OpenDirectory-Signature'], undefined);
    assert.ok(options.signal instanceof AbortSignal);
    return new Response('unavailable', { status: 503 });
  };
  try {
    const delivered = await viaGateway('POST', `/api/gateway/webhooks/${created.body.id}/test`, 'manager', 'gateway-webhook-administrator', {});
    assert.equal(delivered.status, 200);
    assert.equal(delivered.body.success, false);
    assert.equal(delivered.body.responseStatus, 503);
    const deliveries = await viaGateway('GET', `/api/gateway/webhooks/${created.body.id}/deliveries`, 'manager', 'gateway-reader');
    assert.equal(deliveries.status, 200);
    assert.equal(deliveries.body.length, 1);
    assert.equal(deliveries.body[0].id, delivered.body.delivery.id);
    const counts = (await pool.query('SELECT delivery_count,failure_count FROM webhooks WHERE id=$1', [created.body.id])).rows[0];
    assert.deepEqual(counts, { delivery_count: 1, failure_count: 1 });
    assert.equal(attempts, 1);
  } finally { global.fetch = originalFetch; }
});

test('wrong API audience and absent token purpose are rejected even when bypassing the gateway', async () => {
  const wrong = await new SignJWT({ sub: 'manager', jti: randomUUID(), roles: ['admin'], token_use: 'access' }).setProtectedHeader({ alg: 'RS256', kid: 'group-tests' })
    .setIssuer(issuer).setAudience('browser-client').setIssuedAt().setExpirationTime('5m').sign(privateKey);
  for (const base of [policyBase + '/api/licenses/access', `http://127.0.0.1:${gateway.server.address().port}/api/gateway/access`]) {
    const result = await fetch(base, { headers: { Authorization: 'Bearer ' + wrong } });
    assert.ok([401, 403].includes(result.status));
  }
  const result = await api('GET', '/access', 'manager', 'admin', undefined, { token_use: undefined });
  assert.equal(result.status, 403);
});

test('gateway WebSockets authenticate before upgrade, bound subscriptions, and close at the actual token expiry', async () => {
  const WebSocket = require('module').createRequire(path.join(__dirname, '../../../../api-gateway/package.json'))('ws');
  const base = `ws://127.0.0.1:${gateway.server.address().port}/ws`;
  const denied = (url, authorization, status) => new Promise((resolve, reject) => {
    const socket = new WebSocket(url, { headers: authorization ? { Authorization: authorization } : {}, handshakeTimeout: 4000 });
    socket.once('unexpected-response', (_request, response) => { response.resume(); response.once('end', () => { socket.terminate(); assert.equal(response.statusCode, status); resolve(); }); });
    socket.once('open', () => { socket.terminate(); reject(new Error('Unauthorized WebSocket accepted')); });
    socket.on('error', () => {});
  });
  await denied(base, undefined, 401);
  await denied(base + '?token=forged', undefined, 404);
  await denied(base, await token('manager', 'license-manager'), 403);
  const credential = await new SignJWT({ sub: 'manager', jti: randomUUID(), roles: ['gateway-reader'], token_use: 'access' }).setProtectedHeader({ alg: 'RS256', kid: 'group-tests' })
    .setIssuer(issuer).setAudience('opendirectory-api').setIssuedAt().setExpirationTime('2s').sign(privateKey);
  const socket = new WebSocket(base, { headers: { Authorization: 'Bearer ' + credential } });
  const receive = () => new Promise((resolve, reject) => { socket.once('message', data => resolve(JSON.parse(data.toString()))); socket.once('error', reject); });
  const initial = await receive(); assert.equal(initial.type, 'connection');
  const subscribed = receive(); socket.send(JSON.stringify({ type: 'subscribe', data: { service: '../../private' } })); assert.equal((await subscribed).accepted, false);
  const pong = receive(); socket.send(JSON.stringify({ type: 'ping' })); assert.equal((await pong).type, 'pong');
  const code = await new Promise(resolve => socket.once('close', resolve)); assert.equal(code, 4401);
});

test('legacy and canonical routes share one actual license pool, assignment source, capacity and audit identity', async () => {
  const first = await person(); const second = await person(); const license = await product(1);
  assert.equal((await api('POST', `/${license.id}/assign`, 'manager', 'license-manager', { assignee_type: 'user', assignee_id: first })).status, 201);
  const overflow = await legacy('POST', `/licenses/${license.id}/assign`, 'manager', 'license-manager', { assignee_type: 'user', assignee_id: second, assignedBy: 'forged' });
  assert.equal(overflow.status, 409); assert.deepEqual(await assigned(license), [first]);
  const detail = await legacy('GET', `/licenses/${license.id}`, 'manager', 'license-manager');
  assert.equal(detail.status, 200); assert.equal(detail.body.used_seats, 1);
  assert.equal((await legacy('DELETE', `/licenses/${license.id}/assignments/${first}?assignee_type=user`, 'manager', 'license-manager')).status, 204);
  const assignedSecond = await legacy('POST', `/licenses/${license.id}/assign`, 'manager', 'license-manager', { assignee_type: 'user', assignee_id: second, assigned_by: 'forged' });
  assert.equal(assignedSecond.status, 201);
  const operator = (await context()).principal.userId;
  assert.equal(assignedSecond.body.assigned_by, operator);
  const audit = (await pool.query("SELECT actor,actor_subject,actor_issuer FROM license_audit_events WHERE action='assigned' ORDER BY created_at DESC LIMIT 1")).rows[0];
  assert.deepEqual(audit, { actor: operator, actor_subject: 'manager', actor_issuer: issuer });
  assert.deepEqual(await assigned(license), [second]);
});

test('legacy self-service retains canonical ownership and cannot bypass independent review or cost privacy', async () => {
  const userId = await person(); await link('self-alias', userId); const license = await product();
  await pool.query('UPDATE license_catalog SET cost_per_seat=50,notes=$2 WHERE id=$1', [license.id, 'private-procurement-note']);
  assert.equal((await legacy('GET', '/licenses', 'self-alias')).status, 403);
  const kiosk = await legacy('GET', '/kiosk', 'self-alias');
  assert.equal(kiosk.status, 200); assert.equal(kiosk.body.licenses[0].cost_per_seat, undefined); assert.equal(kiosk.body.licenses[0].notes, undefined);
  const created = await legacy('POST', `/licenses/${license.id}/request`, 'self-alias', 'user', { requester_id: 'manager', requester_name: 'forged' });
  assert.equal(created.status, 201); assert.equal(created.body.requester_id, userId); assert.equal(created.body.assignee_id, userId);
  assert.equal(created.body.requester_subject, 'self-alias');
  assert.deepEqual((await legacy('GET', '/requests?requester_id=self-alias', 'requester')).body.requests, []);
  for (const action of ['approve', 'deny']) assert.equal((await legacy('POST', `/requests/${created.body.id}/${action}`, 'self-alias', 'admin', { decided_by: 'independent-reviewer' })).status, 403);
  const approved = await legacy('POST', `/requests/${created.body.id}/approve`, 'independent-reviewer', 'license-approver', { decided_by: 'forged' });
  assert.equal(approved.status, 200); assert.equal(approved.body.decided_by, (await context('independent-reviewer')).principal.userId);
  assert.deepEqual(await assigned(license), [userId]);
});

test('legacy group assignment reports canonical capacity blockage instead of inventing one group seat', async () => {
  const members = await Promise.all([person(), person()]); const groupId = await group(members); const license = await product(1);
  const blocked = await legacy('POST', `/licenses/${license.id}/assign`, 'manager', 'license-manager', { assignee_type: 'group', assignee_id: groupId });
  assert.equal(blocked.status, 202); assert.equal(blocked.body.rule.status, 'capacity-blocked'); assert.deepEqual(await assigned(license), []);
  await pool.query('UPDATE license_catalog SET total_seats=2 WHERE id=$1', [license.id]);
  const reconciled = await legacy('POST', `/licenses/${license.id}/groups/${groupId}/reconcile`, 'manager', 'license-manager', {});
  assert.equal(reconciled.status, 200); assert.deepEqual(await assigned(license), members.sort());
});

test('legacy grants reject disabled or unknown recipients and fail closed on authoritative source outages', async () => {
  const userId = await person(); const license = await product();
  assert.equal((await legacy('POST', `/licenses/${license.id}/assign`, 'manager', 'license-manager', { assignee_type: 'user', assignee_id: randomUUID() })).status, 404);
  await directory.query('UPDATE users SET enabled=false WHERE id=$1', [userId]);
  assert.equal((await legacy('POST', `/licenses/${license.id}/assign`, 'manager', 'license-manager', { assignee_type: 'user', assignee_id: userId })).status, 403);
  bindingMode = 'offline';
  assert.equal((await legacy('POST', `/licenses/${license.id}/assign`, 'manager', 'license-manager', { assignee_type: 'user', assignee_id: userId })).status, 503);
  assert.deepEqual(await assigned(license), []);
});

test('legacy catalog mutation uses the canonical schema and refuses hidden assignments or license-key storage', async () => {
  for (const body of [{ name: 'Unsafe', licenseKey: 'secret-key' }, { name: 'Unsafe', assignments: [{ userId: await person() }] }, { name: 'Unsafe', quantity: 0 }]) {
    const result = await legacy('POST', '/licenses', 'manager', 'license-manager', body);
    assert.equal(result.status, 422); assert.equal(JSON.stringify(result.body).includes('secret-key'), false);
  }
  assert.equal((await pool.query('SELECT COUNT(*)::int AS count FROM license_catalog')).rows[0].count, 0);
  const created = await legacy('POST', '/licenses', 'manager', 'license-manager', { name: 'Canonical Office', vendor: 'Vendor', total_seats: 2 });
  assert.equal(created.status, 201);
  const detail = await api('GET', `/${created.body.id}`, 'manager', 'license-manager');
  assert.equal(detail.status, 200); assert.equal(detail.body.name, 'Canonical Office'); assert.equal(detail.body.total_seats, 2);
});

test('legacy lifecycle routes keep offboarding separate from allocation and reactivation', async () => {
  const userId = await person(); const license = await product(); await direct(license, userId);
  assert.equal((await legacy('POST', `/users/${userId}/offboard`, 'manager', 'license-manager', {})).status, 403);
  assert.equal((await legacy('POST', `/users/${userId}/offboard`, 'manager', 'user-lifecycle-operator', {})).status, 200);
  assert.equal((await legacy('POST', `/users/${userId}/activate`, 'manager', 'user-lifecycle-operator', {})).status, 403);
  assert.deepEqual(await assigned(license), []);
  assert.equal((await legacy('POST', `/licenses/${license.id}/assign`, 'manager', 'license-manager', { assignee_type: 'user', assignee_id: userId })).status, 403);
});

test('legacy routes verify actual signed JWTs and bound identities rather than gateway/body administrative claims', async () => {
  const license = await product();
  assert.equal((await legacy('POST', '/licenses', 'requester', 'user', { name: 'Forged', roles: ['admin'] })).status, 403);
  assert.equal((await legacy('GET', '/licenses', 'unmapped', 'admin')).status, 403);
  assert.equal((await legacy('GET', '/licenses', 'manager', 'admin', undefined, { token_use: 'id' })).status, 403);
  const raw = await fetch(`http://127.0.0.1:${adapter.server.address().port}/api/license/licenses`, { headers: { Authorization: 'Bearer forged-token', 'X-User-Roles': 'admin' } });
  assert.equal(raw.status, 403);
  assert.deepEqual(await assigned(license), []);
});

test('retired WebSocket upgrades use the same real JWT verifier and never open an alternate license stream', async () => {
  const upgrade = authorization => new Promise((resolve, reject) => {
    const request = http.request(`http://127.0.0.1:${adapter.server.address().port}/ws/license`, { headers: { Connection: 'Upgrade', Upgrade: 'websocket',
      'Sec-WebSocket-Key': Buffer.alloc(16, 1).toString('base64'), 'Sec-WebSocket-Version': '13', ...(authorization ? { Authorization: authorization } : {}) } });
    request.on('response', response => { response.resume(); response.on('end', () => resolve(response.statusCode)); });
    request.on('upgrade', (_response, socket) => { socket.destroy(); reject(new Error('Legacy event stream unexpectedly opened')); });
    request.on('error', reject); request.end();
  });
  assert.equal(await upgrade(), 401);
  assert.equal(await upgrade('Bearer forged-token'), 403);
  assert.equal(await upgrade(await token('unlinked', 'admin')), 403);
  assert.equal(await upgrade(await token('manager', 'admin', { token_use: 'id' })), 403);
  const expired = await new SignJWT({ sub: 'manager', jti: randomUUID(), roles: ['admin'], token_use: 'access' }).setProtectedHeader({ alg: 'RS256', kid: 'group-tests' })
    .setIssuer(issuer).setAudience('opendirectory-api').setIssuedAt().setExpirationTime(Math.floor(Date.now() / 1000) - 60).sign(privateKey);
  assert.equal(await upgrade(`Bearer ${expired}`), 401);
  assert.equal(await upgrade(await token('manager', 'license-manager')), 410);
  bindingMode = 'offline'; assert.equal(await upgrade(await token('manager', 'admin')), 503);
});

test('direct assignment and delegated requests reject unknown or inactive authoritative users, ignoring body status', async () => {
  const userId = await person(); const license = await product(2, true);
  for (const route of ['assign', 'request']) {
    const unknown = await api('POST', `/${license.id}/${route}`, 'manager', 'license-manager', { assignee_type: 'user', assignee_id: randomUUID(), enabled: true });
    assert.equal(unknown.status, 404);
  }
  await directory.query('UPDATE users SET enabled=false WHERE id=$1', [userId]);
  for (const route of ['assign', 'request']) {
    const inactive = await api('POST', `/${license.id}/${route}`, 'manager', 'license-manager', { assignee_type: 'user', assignee_id: userId, enabled: true, revision: '999999999' });
    assert.equal(inactive.status, 403);
  }
  assert.deepEqual(await assigned(license), []);
  assert.equal((await pool.query('SELECT COUNT(*)::int AS count FROM license_requests')).rows[0].count, 0);
});

test('a disabled requester cannot receive approval for a still-enabled delegated beneficiary or group', async () => {
  const userId = await person(); const license = await product(); const requester = (await context()).principal.userId;
  for (const target of [{ assignee_type: 'user', assignee_id: userId }, { assignee_type: 'group', assignee_id: await group([userId]) }]) {
    const created = await api('POST', `/${license.id}/request`, 'manager', 'license-manager', target);
    assert.equal(created.status, 201);
  }
  await directory.query('UPDATE users SET enabled=false WHERE id=$1', [requester]);
  const requests = (await pool.query('SELECT id FROM license_requests ORDER BY id')).rows;
  assert.equal((await api('POST', `/requests/${requests[0].id}/approve`, 'independent-reviewer', 'license-approver', {})).status, 403);
  assert.deepEqual((await pool.query('SELECT DISTINCT status FROM license_requests')).rows.map(row => row.status), ['cancelled']);
  assert.deepEqual(await assigned(license), []);
});

test('disabling a direct beneficiary before review cancels the request instead of allocating a seat', async () => {
  const userId = await person(); const license = await product();
  const created = await api('POST', `/${license.id}/request`, 'manager', 'license-manager', { assignee_type: 'user', assignee_id: userId });
  await directory.query('UPDATE users SET enabled=false WHERE id=$1', [userId]);
  assert.equal((await api('POST', `/requests/${created.body.id}/approve`, 'independent-reviewer', 'license-approver', {})).status, 403);
  assert.equal((await pool.query('SELECT status FROM license_requests')).rows[0].status, 'cancelled');
  assert.deepEqual(await assigned(license), []);
});

test('authoritative deletion releases direct/group sources and pending requests atomically without setting local offboarding', async () => {
  const userId = await person(); await link('leaver', userId); const first = await product(); const second = await product();
  await direct(first, userId); await grant(first, await group([userId])); await direct(second, userId);
  const pending = await product(); assert.equal((await api('POST', `/${pending.id}/request`, 'leaver', 'user', {})).status, 201);
  await directory.query('DELETE FROM users WHERE id=$1', [userId]);
  const result = await api('POST', `/users/${userId}/reconcile`, 'manager', 'license-manager', { enabled: true, deleted: false });
  assert.equal(result.status, 200); assert.equal(result.body.assignmentsRevoked, 2); assert.equal(result.body.requestsCancelled, 1);
  assert.equal(result.body.deleted, true); assert.equal(result.body.disabled, false);
  assert.equal((await pool.query('SELECT COUNT(*)::int AS count FROM license_assignment_sources WHERE user_id=$1', [userId])).rows[0].count, 0);
  assert.deepEqual(await assigned(first), []); assert.deepEqual(await assigned(second), []);
  const repeated = await api('POST', `/users/${userId}/reconcile`, 'manager', 'license-manager', {});
  assert.equal(repeated.body.assignmentsRevoked, 0);
  assert.equal((await api('POST', `/users/${userId}/activate`, 'manager', 'admin', {})).status, 403);
});

test('directory re-enablement never clears a local offboarding marker or silently restores direct grants', async () => {
  const userId = await person(); const license = await product(); await direct(license, userId);
  await directory.query('UPDATE users SET enabled=false WHERE id=$1', [userId]);
  const authentication = await context();
  await allocator.users.reconcile(userId, 'manager', authentication);
  assert.deepEqual(await assigned(license), []);
  assert.equal((await api('POST', `/users/${userId}/activate`, 'manager', 'admin', {})).status, 403);
  await allocator.offboard(userId, 'operator');
  await directory.query('UPDATE users SET enabled=true WHERE id=$1', [userId]);
  const refreshed = await allocator.users.reconcile(userId, 'manager', authentication);
  assert.equal(refreshed.enabled, true); assert.equal(refreshed.disabled, true);
  await assert.rejects(direct(license, userId), { status: 403 });
  await allocator.activate(userId, 'operator', authentication);
  assert.deepEqual(await assigned(license), []);
  await direct(license, userId); assert.deepEqual(await assigned(license), [userId]);
});

test('source outages and unknown identities preserve last confirmed entitlements, not a guessed disabled or enabled state', async () => {
  const userId = await person(); const license = await product(); await direct(license, userId);
  const before = (await pool.query('SELECT directory_revision,directory_enabled FROM license_subjects WHERE user_id=$1', [userId])).rows[0];
  for (const status of [403, 404, 503]) {
    userMode = status;
    const result = await api('POST', `/users/${userId}/reconcile`, 'manager', 'license-manager', {});
    assert.equal(result.status, status);
    const another = await product();
    assert.equal((await api('POST', `/${another.id}/assign`, 'manager', 'license-manager', { assignee_type: 'user', assignee_id: userId })).status, status);
    assert.deepEqual(await assigned(license), [userId]);
    assert.deepEqual((await pool.query('SELECT directory_revision,directory_enabled FROM license_subjects WHERE user_id=$1', [userId])).rows[0], before);
  }
});

test('a stale positive source response arriving after confirmed disablement cannot regrant a direct seat', async () => {
  const userId = await person(); const license = await product(); const authentication = await context();
  let observed; const read = new Promise(resolve => { observed = resolve; }); let release; const waiting = new Promise(resolve => { release = resolve; });
  const delayed = new LicenseAllocator(allocator.database, { source: { user: async (identifier, authorization) => {
    const snapshot = await client.user(identifier, authorization); observed(); await waiting; return snapshot;
  } } });
  const assigning = delayed.assign(license.id, { assignee_type: 'user', assignee_id: userId }, 'manager', authentication);
  const outcome = assigning.then(() => null, error => error);
  await read;
  try {
    await directory.query('UPDATE users SET enabled=false WHERE id=$1', [userId]);
    await allocator.users.reconcile(userId, 'manager', authentication);
  } finally { release(); }
  assert.equal((await outcome).status, 409);
  assert.deepEqual(await assigned(license), []);
});

test('an older negative snapshot cannot revoke a subsequently re-enabled and explicitly assigned user', async () => {
  const userId = await person(); const license = await product(); const authentication = await context();
  await directory.query('UPDATE users SET enabled=false WHERE id=$1', [userId]);
  const old = await client.user(userId, authentication.authorization);
  await allocator.users.reconcileSnapshot(old, 'manager');
  await directory.query('UPDATE users SET enabled=true WHERE id=$1', [userId]);
  await direct(license, userId);
  await assert.rejects(allocator.users.reconcileSnapshot(old, 'manager'), { status: 409 });
  userMode = snapshot => ({ ...snapshot, enabled: false });
  await assert.rejects(allocator.users.reconcile(userId, 'manager', authentication), { status: 409 });
  assert.deepEqual(await assigned(license), [userId]);
});

test('a stored negative eligibility fence also blocks an older active group snapshot', async () => {
  const userId = await person(); const groupId = await group([userId]); const license = await product(); const authentication = await context();
  await grant(license, groupId); const old = await client.snapshot(groupId, authentication.authorization);
  await directory.query('UPDATE users SET enabled=false WHERE id=$1', [userId]);
  await allocator.users.reconcile(userId, 'manager', authentication);
  sourceMode = () => old;
  await reconcile(license, groupId);
  assert.deepEqual(await assigned(license), []);
});

test('user reconciliation audit failure rolls back eligibility fences, seat releases, and request cancellation', async () => {
  const userId = await person(); const license = await product(); await direct(license, userId); const pending = await product();
  assert.equal((await api('POST', `/${pending.id}/request`, 'manager', 'license-manager', { assignee_type: 'user', assignee_id: userId })).status, 201);
  const revision = (await pool.query('SELECT directory_revision FROM license_subjects WHERE user_id=$1', [userId])).rows[0].directory_revision;
  await directory.query('UPDATE users SET enabled=false WHERE id=$1', [userId]);
  const failing = new LicenseAllocator({ query: allocator.database.query, getClient: async () => {
    const connection = await pool.connect();
    return { release: () => connection.release(), query: (sql, parameters) => sql.startsWith('INSERT INTO license_audit_events') && parameters[1] === 'directory-revoked'
      ? Promise.reject(new Error('eligibility audit outage')) : connection.query(sql, parameters) };
  } }, { source: client });
  await assert.rejects(failing.users.reconcile(userId, 'manager', await context()), /eligibility audit outage/);
  assert.deepEqual(await assigned(license), [userId]);
  assert.equal((await pool.query('SELECT status FROM license_requests WHERE license_id=$1', [pending.id])).rows[0].status, 'pending');
  assert.equal((await pool.query('SELECT directory_revision FROM license_subjects WHERE user_id=$1', [userId])).rows[0].directory_revision, revision);
});

test('background reconciliation is bounded, rotates through users, and stops on source credential outages', async () => {
  const users = Array.from({ length: 51 }, () => randomUUID()); const license = await product(0);
  await directory.query("INSERT INTO users(id,username,email) SELECT identifier,identifier::text,identifier::text || '@test.invalid' FROM unnest($1::uuid[]) AS identifier", [users]);
  await pool.query("INSERT INTO license_assignment_sources(license_id,user_id,source_type,source_id,assigned_by) SELECT $1,identifier,'direct','direct','owned-import' FROM unnest($2::text[]) AS identifier",[license.id,users]);
  await pool.query("INSERT INTO license_assignments(license_id,assignee_type,assignee_id) SELECT $1,'user',identifier FROM unnest($2::text[]) AS identifier", [license.id, users]);
  const authorization = (await context('worker', 'license-eligibility-reader')).authorization;
  const first = await allocator.users.reconcileAll(authorization); assert.equal(first.length, 50);
  await allocator.users.reconcileAll(authorization);
  assert.equal((await pool.query('SELECT COUNT(*)::int AS count FROM license_subjects WHERE directory_checked_at IS NOT NULL')).rows[0].count, 51);
  userMode = 403;
  const stopped = await allocator.users.reconcileAll(authorization); assert.equal(stopped.length, 1); assert.ok(stopped[0].error);
  assert.equal((await assigned(license)).length, 51);
  assert.equal((await pool.query('SELECT COUNT(*)::int AS count FROM license_subjects WHERE directory_error IS NOT NULL')).rows[0].count, 1);
});

test('eligibility UI endpoints are permission-gated and never trust body-provided revisions', async () => {
  const userId = await person(); const license = await product(); await direct(license, userId);
  assert.equal((await api('GET', '/users', 'requester', 'user')).status, 403);
  assert.equal((await api('POST', `/users/${userId}/reconcile`, 'requester', 'license-reader', {})).status, 403);
  const updated = await api('POST', `/users/${userId}/reconcile`, 'manager', 'license-manager', { enabled: false, deleted: true, revision: '999999999' });
  assert.equal(updated.status, 200); assert.equal(updated.body.enabled, true); assert.equal(updated.body.deleted, false);
  const states = await api('GET', '/users', 'requester', 'license-reader');
  assert.equal(states.status, 200); assert.ok(states.body.users.some(state => state.user_id === userId && state.directory_enabled === true));
  await pool.query(policyMigration('008_user_eligibility.sql'));
  const revision = BigInt(updated.body.revision);
  await assert.rejects(pool.query('UPDATE license_subjects SET directory_revision=$2 WHERE user_id=$1', [userId, String(revision - 1n)]), error => error.code === '23514');
  await assert.rejects(pool.query('UPDATE license_subjects SET directory_enabled=false WHERE user_id=$1', [userId]), error => error.code === '23514');
});

test('a worker-confirmed disablement racing a direct grant leaves no entitlement after both finish', async () => {
  const userId = await person(); const license = await product(); const authentication = await context();
  const sourceState = await client.user(userId, authentication.authorization);
  const stale = new LicenseAllocator(allocator.database, { source: { user: async () => sourceState } });
  await directory.query('UPDATE users SET enabled=false WHERE id=$1', [userId]);
  const results = await Promise.allSettled([
    stale.assign(license.id, { assignee_type: 'user', assignee_id: userId }, 'manager', authentication),
    allocator.users.reconcile(userId, 'manager', authentication),
  ]);
  assert.equal(results[1].status, 'fulfilled'); assert.deepEqual(await assigned(license), []);
});

test('revoking a group preserves a direct source, and revoking a direct source preserves a group', async () => {
  const userId = await person(); const groupId = await group([userId]); const license = await product(1);
  await direct(license, userId); await grant(license, groupId);
  await allocator.revoke(license.id, groupId, 'manager', 'group');
  assert.deepEqual(await assigned(license), [userId]);
  await grant(license, groupId); await allocator.revoke(license.id, userId, 'manager', 'user');
  assert.deepEqual(await assigned(license), [userId]);
  await assert.rejects(allocator.revoke(license.id, userId, 'manager', 'user'), { status: 409 });
});

test('adding a direct grant to a group-licensed user does not consume another seat', async () => {
  const userId = await person(); const license = await product(1); await grant(license, await group([userId]));
  await direct(license, userId);
  await assert.rejects(direct(license, userId), { status: 409 });
  assert.deepEqual(await assigned(license), [userId]);
});

test('approving an earlier direct request preserves its source even when a group granted the seat meanwhile', async () => {
  const userId = await person(); const groupId = await group([userId]); const license = await product(1);
  const request = await requestLicense(license.id, { requester_id: 'requester', assignee_type: 'user', assignee_id: userId });
  await grant(license, groupId);
  await reviewLicense(request.record.id, 'independent-reviewer', 'approved');
  await groups.revoke(license.id, groupId, 'manager');
  assert.deepEqual(await assigned(license), [userId]);
  assert.deepEqual((await pool.query('SELECT source_type FROM license_assignment_sources')).rows.map(row => row.source_type), ['direct']);
});

test('removing one group source preserves overlapping access and the last removal releases the seat', async () => {
  const userId = await person(); const first = await group([userId]); const second = await group([userId]); const license = await product(1);
  await grant(license, first); await grant(license, second);
  for (const groupId of [first, second]) {
    await directory.query('DELETE FROM group_members WHERE group_id=$1 AND user_id=$2', [groupId, userId]);
    await reconcile(license, groupId);
    assert.deepEqual(await assigned(license), groupId === first ? [userId] : []);
  }
});

test('insufficient capacity persists an honest blocked rule and later retries converge', async () => {
  const users = await Promise.all([person(), person()]); const groupId = await group(users); const license = await product(1);
  assert.equal((await grant(license, groupId)).rule.status, 'capacity-blocked');
  assert.deepEqual(await assigned(license), []);
  await pool.query('UPDATE license_catalog SET total_seats=2 WHERE id=$1', [license.id]);
  assert.equal((await reconcile(license, groupId)).rule.status, 'active');
  assert.deepEqual(await assigned(license), users.sort());
});

test('capacity shortages never retain departed members to make room for incomplete additions', async () => {
  const users = await Promise.all([person(), person(), person(), person()]); const groupId = await group(users.slice(0, 2)); const license = await product(2);
  await grant(license, groupId);
  await directory.query('DELETE FROM group_members WHERE group_id=$1 AND user_id=$2', [groupId, users[0]]);
  for (const userId of users.slice(2)) await directory.query('INSERT INTO group_members(group_id,user_id) VALUES($1,$2)', [groupId, userId]);
  assert.equal((await reconcile(license, groupId)).rule.status, 'capacity-blocked');
  assert.deepEqual(await assigned(license), [users[1]]);
});

test('concurrent group and direct allocations cannot overbook a finite pool', async () => {
  const users = await Promise.all([person(), person(), person()]); const groupId = await group(users.slice(0, 2)); const license = await product(2);
  await Promise.allSettled([grant(license, groupId), direct(license, users[2])]);
  assert.ok((await assigned(license)).length <= 2);
  const counters = (await pool.query('SELECT used_seats FROM license_catalog WHERE id=$1', [license.id])).rows[0];
  assert.equal(counters.used_seats, (await assigned(license)).length);
});

test('retries with the same authoritative version do not duplicate sources or seat use', async () => {
  const userId = await person(); const groupId = await group([userId]); const license = await product(1);
  await grant(license, groupId); await grant(license, groupId); await reconcile(license, groupId);
  assert.deepEqual(await assigned(license), [userId]);
  assert.equal((await pool.query('SELECT COUNT(*)::int AS count FROM license_assignment_sources')).rows[0].count, 1);
});

test('older or conflicting snapshots cannot undo the last applied membership', async () => {
  const userId = await person(); const groupId = await group([userId]); const license = await product(); await grant(license, groupId);
  sourceMode = snapshot => ({ ...snapshot, revision: '1', memberIds: [],memberships:[] });
  await assert.rejects(reconcile(license, groupId), { status: 409 });
  sourceMode = snapshot => ({ ...snapshot, memberIds: [],memberships:[] });
  await assert.rejects(reconcile(license, groupId), { status: 409 });
  assert.deepEqual(await assigned(license), [userId]);
});

test('unresolved or unavailable sources fail closed and expose synchronization errors', async () => {
  const userId = await person(); const groupId = await group([userId]); const license = await product(); await grant(license, groupId);
  sourceMode = snapshot => ({ ...snapshot, unresolvedMemberIds: ['missing-account'] });
  await assert.rejects(reconcile(license, groupId), { status: 503 });
  sourceMode = 'offline';
  await groups.reconcileAll((await context('worker', 'license-group-reader')).authorization);
  assert.ok((await pool.query('SELECT last_error FROM license_group_rules')).rows[0].last_error);
  assert.deepEqual(await assigned(license), [userId]);
});

test('authoritative tombstones revoke only the deleted group source', async () => {
  const userId = await person(); const groupId = await group([userId]); const license = await product(); await direct(license, userId); await grant(license, groupId);
  await directory.query('DELETE FROM groups WHERE id=$1', [groupId]);
  await groups.reconcileAll((await context('worker', 'license-group-reader')).authorization);
  assert.equal((await pool.query('SELECT status FROM license_group_rules')).rows[0].status, 'deleted');
  assert.deepEqual(await assigned(license), [userId]);
});

test('beneficiaries cannot review group requests through an unrelated JWT subject alias', async () => {
  const userId = await person(); await link('reviewer-alias', userId); const groupId = await group([userId]); const license = await product();
  const request = await requestLicense(license.id, { requester_id: 'manager', assignee_type: 'group', assignee_id: groupId }, await context());
  for (const decision of ['approved', 'denied']) await assert.rejects(reviewLicense(request.record.id, 'reviewer-alias', decision, await context('reviewer-alias', 'license-approver')), { status: 403 });
  assert.deepEqual(await assigned(license), []);
});

test('reviewers require an enabled authoritative identity link, not a guessed subject match', async () => {
  const groupId = await group([await person()]); const license = await product();
  const request = await requestLicense(license.id, { requester_id: 'manager', assignee_type: 'group', assignee_id: groupId }, await context());
  await assert.rejects(reviewLicense(request.record.id, 'reviewer', 'approved', await context('reviewer', 'license-approver')), { status: 403 });
  const reviewer = await person(); await link('reviewer', reviewer);
  assert.equal((await reviewLicense(request.record.id, 'reviewer', 'approved', await context('reviewer', 'license-approver'))).allocation_status, 'active');
});

test('automatic group approval reports blocked allocation rather than pretending licenses were delivered', async () => {
  const groupId = await group([await person(), await person()]); const license = await product(1, true);
  const request = await requestLicense(license.id, { requester_id: 'manager', assignee_type: 'group', assignee_id: groupId }, await context());
  assert.equal(request.record.status, 'approved'); assert.equal(request.record.allocation_status, 'capacity-blocked');
  assert.deepEqual(await assigned(license), []);
});

test('offboarding removes every source and same-version reconciliation cannot relicense a disabled user', async () => {
  const userId = await person(); const groupId = await group([userId]); const license = await product(); await direct(license, userId); await grant(license, groupId);
  await allocator.offboard(userId, 'operator'); await reconcile(license, groupId);
  assert.deepEqual(await assigned(license), []);
  assert.equal((await pool.query('SELECT COUNT(*)::int AS count FROM license_assignment_sources')).rows[0].count, 0);
  await allocator.activate(userId, 'operator', await context()); await reconcile(license, groupId);
  assert.deepEqual(await assigned(license), [userId]);
  assert.deepEqual((await pool.query('SELECT source_type FROM license_assignment_sources')).rows.map(row => row.source_type), ['group']);
});

test('a group reconciliation racing with offboarding cannot leave a source on a disabled user', async () => {
  const userId = await person(); const groupId = await group([userId]); const license = await product(1);
  const results = await Promise.allSettled([grant(license, groupId), allocator.offboard(userId, 'offboarding-operator')]);
  assert.equal(results[1].status, 'fulfilled');
  assert.deepEqual(await assigned(license), []);
  assert.equal((await pool.query('SELECT COUNT(*)::int AS count FROM license_assignment_sources WHERE user_id=$1', [userId])).rows[0].count, 0);
});

test('expiring a direct source preserves an indefinite group entitlement', async () => {
  const userId = await person(); const groupId = await group([userId]); const license = await product();
  await direct(license, userId, new Date(Date.now() + 250).toISOString()); await grant(license, groupId);
  await new Promise(resolve => setTimeout(resolve, 300)); await allocator.expireAll();
  assert.deepEqual(await assigned(license), [userId]);
  assert.deepEqual((await pool.query('SELECT source_type FROM license_assignment_sources')).rows.map(row => row.source_type), ['group']);
});

test('expiring a group rule preserves a direct grant and disables future group grants', async () => {
  const userId = await person(); const groupId = await group([userId]); const license = await product(); await direct(license, userId);
  await grant(license, groupId, 'manager', new Date(Date.now() + 250).toISOString());
  await new Promise(resolve => setTimeout(resolve, 300)); await allocator.expireAll();
  assert.deepEqual(await assigned(license), [userId]);
  assert.equal((await pool.query('SELECT status FROM license_group_rules')).rows[0].status, 'expired');
});

test('manual revocation fences a worker snapshot fetched before the revocation', async () => {
  const userId = await person(); const groupId = await group([userId]); const license = await product(); await grant(license, groupId);
  const snapshot = await groups.snapshot(groupId, await context()); await groups.revoke(license.id, groupId, 'manager');
  await groups.inPool(license.id, snapshot, 'system:worker', (connection, catalog, disabled) => groups.apply(connection, catalog, snapshot, 'system:worker', disabled), { systemActor: true });
  assert.deepEqual(await assigned(license), []);
});

test('audit failures roll back group rules, releases and new materialized seats together', async () => {
  const userId = await person(); const groupId = await group([userId]); const license = await product();
  const failing = new LicenseAllocator({ query: (sql, parameters) => pool.query(sql, parameters), getClient: async () => {
    const connection = await pool.connect();
    return { release: () => connection.release(), query: (sql, parameters) => sql.startsWith('INSERT INTO license_audit_events') ? Promise.reject(new Error('audit outage')) : connection.query(sql, parameters) };
  } });
  new GroupLicenseAllocator({ allocator: failing, source: client });
  await assert.rejects(failing.assign(license.id, { assignee_type: 'group', assignee_id: groupId }, 'manager', await context()), /audit outage/);
  assert.deepEqual(await assigned(license), []);
  assert.equal((await pool.query('SELECT COUNT(*)::int AS count FROM license_group_rules')).rows[0].count, 0);
  await grant(license, groupId);
  const revision = (await pool.query('SELECT source_revision FROM license_group_rules')).rows[0].source_revision;
  const replacement = await person();
  await directory.query('DELETE FROM group_members WHERE group_id=$1 AND user_id=$2', [groupId, userId]);
  await directory.query('INSERT INTO group_members(group_id,user_id) VALUES($1,$2)', [groupId, replacement]);
  await assert.rejects(failing.assign(license.id, { assignee_type: 'group', assignee_id: groupId }, 'manager', await context()), /audit outage/);
  assert.deepEqual(await assigned(license), [userId]);
  assert.equal((await pool.query('SELECT source_revision FROM license_group_rules')).rows[0].source_revision, revision);
});

test('migration reapplication never invents direct grants for users licensed only by groups', async () => {
  const userId = await person(); const groupId = await group([userId]); const license = await product(); await grant(license, groupId);
  await pool.query(policyMigration('006_group_license_sources.sql'));
  await groups.revoke(license.id, groupId, 'manager');
  assert.deepEqual(await assigned(license), []);
});

test('UUID casing cannot duplicate a direct/group entitlement or bypass offboarding', async () => {
  const userId = await person(); const groupId = await group([userId]); const license = await product(1); await grant(license, groupId);
  await direct(license, userId.toUpperCase());
  assert.deepEqual(await assigned(license), [userId]);
  await allocator.offboard(userId.toUpperCase(), 'operator'); await reconcile(license, groupId);
  assert.deepEqual(await assigned(license), []);
});

test('upgrading legacy group and UUID-alias records preserves direct grants without fake group seats', async () => {
  const schema = `legacy_groups_${randomUUID().replaceAll('-', '')}`;
  await administration.query(`CREATE SCHEMA ${schema}`);
  const legacy = new Pool({ connectionString, max: 1, options: `-c search_path=${schema},public` });
  try {
    await legacy.query(policyMigration('004_licenses.sql')); await legacy.query(policyMigration('005_license_allocation.sql'));
    const licenseId = (await legacy.query("INSERT INTO license_catalog(name,total_seats) VALUES('Legacy',4) RETURNING id")).rows[0].id;
    const userId = 'abcdefab-1111-4111-8111-111111111111'; const groupId = 'fedcbafe-2222-4222-8222-222222222222';
    for (const assignee of [userId, userId.toUpperCase()]) await legacy.query("INSERT INTO license_assignments(license_id,assignee_type,assignee_id,assigned_by) VALUES($1,'user',$2,'old-manager')", [licenseId, assignee]);
    await legacy.query("INSERT INTO license_assignments(license_id,assignee_type,assignee_id,assigned_by) VALUES($1,'group',$2,'old-manager')", [licenseId, groupId.toUpperCase()]);
    await legacy.query(policyMigration('006_group_license_sources.sql'));
    assert.deepEqual((await legacy.query('SELECT assignee_id FROM license_assignments')).rows.map(row => row.assignee_id), [userId]);
    assert.equal((await legacy.query('SELECT used_seats FROM license_catalog')).rows[0].used_seats, 1);
    assert.equal((await legacy.query('SELECT group_id,status FROM license_group_rules')).rows[0].group_id, groupId);
    assert.equal((await legacy.query('SELECT status FROM license_group_rules')).rows[0].status, 'pending');
    assert.equal((await legacy.query('SELECT COUNT(*)::int AS count FROM license_assignment_sources')).rows[0].count, 1);
    await legacy.query(policyMigration('006_group_license_sources.sql'));
    assert.equal((await legacy.query('SELECT COUNT(*)::int AS count FROM license_assignment_sources')).rows[0].count, 1);
  } finally { await legacy.end(); await administration.query(`DROP SCHEMA ${schema} CASCADE`); }
});
