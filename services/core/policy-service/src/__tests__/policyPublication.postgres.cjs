'use strict';

const { test, before, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { Pool } = require('pg');
const { PolicyConfiguration, etag, context } = require('../PolicyConfiguration');
const { publicationTag } = require('../PolicyPublication');
const schema = 'publication_' + randomUUID().replaceAll('-', '');
const administration = new Pool({ connectionString: process.env.LICENSE_TEST_DATABASE_URL, max: 1 });
const managerId = randomUUID(); const reviewerId = randomUUID(); const otherId = randomUUID();
const confirmation = { reason: 'Explicit independently confirmed publication scope', acknowledgeScope: true };
let pool; let store; let sourceRows; let authorityHook; let sourceHook; let authorityCalls; let sourceCalls;
function actor(id = managerId, roles = ['policy-administrator']) {
  const authTime = Math.floor(Date.now() / 1000);
  return { actor_type: 'user', token_use: 'access', iss: 'https://publication.test', sub: 'owned-' + id, client_id: 'owned-client', jti: randomUUID(),
    exp: authTime + 3600, iat: authTime, roles, identity_authorization: { userId: id, revision: '1', linkRevision: '1', rolesRevision: 'a'.repeat(64) },
    auth_time: authTime, amr: ['pwd', 'otp'], mfa_authorization: { schemaVersion: 1, userId: id, revision: '1', authTime, methods: ['pwd', 'otp'] } };
}
const bearer = 'Bearer owned.original.actor';
const reviewer = () => actor(reviewerId, ['policy-publication-reviewer']);
const draft = () => store.create({ name: 'Owned reviewed policy', type: 'security', settings: { password: 'not-copied-to-publication-audit' }, ...confirmation }, actor(), bearer);
async function requested(kind, row, voterId = reviewerId, who = actor()) {
  const frame = await store.publications.get(kind, row.id, who, bearer);
  return store.publications.request(kind, row.id, etag(kind, row), { reviewerUserId: voterId, validitySeconds: 300, configurationHash: frame.configurationHash, ...confirmation }, who, bearer);
}
const decision = (kind, row, publication, state = 'approved', who = reviewer()) => store.publications.transition(kind, row.id, publication.id, publicationTag(publication),
  { decision: state, resourceVersion: row.version, configurationHash: publication.configurationHash, ...confirmation }, who, bearer);
const activate = (row, publication, who = actor()) => store.mutate(row.id, etag('policy', row), { publicationId: publication.id, ...confirmation }, who, bearer, 'activated');
before(async () => {
  await administration.query(`CREATE SCHEMA ${schema}`); const url = new URL(process.env.LICENSE_TEST_DATABASE_URL); url.searchParams.set('options', `-c search_path=${schema},public`);
  pool = new Pool({ connectionString: url.toString(), max: 8 });
  for (const file of ['001_policies.sql', '003_blueprints.sql', '018_policy_configuration.sql', '019_policy_publication.sql']) await pool.query(fs.readFileSync(path.join(__dirname, '../db/migrations', file), 'utf8'));
});
beforeEach(async () => {
  await pool.query("CREATE OR REPLACE FUNCTION policy_configuration_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp(); $$");
  await pool.query('TRUNCATE policy_publication_outbox,policy_publication_audit,policy_publications,policy_publication_heads,policy_configuration_outbox,policy_configuration_audit,policy_configuration_origins,policy_assignments,policy_links,policies,blueprint_assignments,blueprint_configurations,blueprints CASCADE');
  sourceRows = new Map([[managerId, { enabled: true, linked: true, requestRevision: 'b'.repeat(64), reviewRevision: null }],
    [reviewerId, { enabled: true, linked: true, requestRevision: null, reviewRevision: 'c'.repeat(64) }],
    [otherId, { enabled: true, linked: true, requestRevision: null, reviewRevision: 'd'.repeat(64) }]]);
  authorityHook = null; sourceHook = null; authorityCalls = 0; sourceCalls = 0;
  store = new PolicyConfiguration({ getClient: () => pool.connect(), query: (...args) => pool.query(...args) }, {
    authority: async () => { authorityCalls++; if (authorityHook) await authorityHook(authorityCalls); },
    publicationSource: { actor: async id => { sourceCalls++; if (sourceHook) await sourceHook(sourceCalls); return sourceRows.get(id) || { enabled: false, linked: false }; } },
  });
});
after(async () => { if (pool) await pool.end(); await administration.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`); await administration.end(); });

test('publication is mandatory and genuinely independent, not a bypass for an administrator or an invented reviewer alias', async () => {
  const row = await draft();
  await assert.rejects(store.mutate(row.id, etag('policy', row), confirmation, actor(), bearer, 'activated'), { status: 400 });
  await assert.rejects(activate(row, { id: randomUUID() }, actor(managerId, ['admin'])), { status: 409 });
  await assert.rejects(requested('policy', row, managerId), { status: 403 });
  const pending = await requested('policy', row);
  await assert.rejects(decision('policy', row, pending, 'approved', actor(managerId, ['admin'])), { status: 403 });
  await assert.rejects(decision('policy', row, pending, 'approved', actor(otherId, ['policy-publication-reviewer'])), { status: 403 });
  await assert.rejects(activate(row, pending), { status: 409 });
  const approved = await decision('policy', row, pending); const active = await activate(row, approved);
  assert.equal(active.status, 'active'); assert.equal(active.version, 2);
  const audit = (await pool.query('SELECT * FROM policy_publication_audit ORDER BY version')).rows;
  assert.deepEqual(audit.map(row => row.action), ['requested', 'approved']); assert.equal(audit[1].actor.userId, reviewerId);
  assert.equal(JSON.stringify(audit).includes('not-copied-to-publication-audit'), false);
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM policy_publication_outbox')).rows[0].count, 2);
});
test('all canonical content contributors are excluded even when they later hold the separate review role under another subject', async () => {
  const row = await draft(); const contributor = actor(reviewerId, ['policy-administrator', 'policy-publication-reviewer']);
  const changed = await store.mutate(row.id, etag('policy', row), { settings: { modifiedBy: 'different-contributor' }, ...confirmation }, contributor, bearer, 'updated');
  sourceRows.get(reviewerId).requestRevision = 'e'.repeat(64);
  await assert.rejects(requested('policy', changed), { status: 403 });
  const pending = await requested('policy', changed, otherId); assert.equal(pending.state, 'pending');
});
test('changing active content, including a no-op edit, makes it a draft and irreversibly invalidates the captured approval generation', async () => {
  const row = await draft(); const approved = await decision('policy', row, await requested('policy', row)); const active = await activate(row, approved);
  const changed = await store.mutate(row.id, etag('policy', active), { settings: active.settings, ...confirmation }, actor(), bearer, 'updated');
  assert.equal(changed.status, 'draft'); assert.equal(changed.version, 3);
  await assert.rejects(activate(changed, approved), { status: 409 });
  assert.equal((await store.publications.get('policy', row.id, actor(), bearer)).publications[0].current, false);
});
test('target changes and blueprint payloads belong to the exact reviewed frame and cannot borrow an old publication', async () => {
  const blueprint = await store.blueprint({ name: 'Owned reviewed blueprint', ...confirmation }, actor(), bearer);
  const configuration = await store.child('blueprint', blueprint.id, etag('blueprint', blueprint), { config_type: 'screen_lock', config_name: 'Owned lock', payload: { seconds: 120 }, ...confirmation }, actor(), bearer, 'configuration_added');
  const pending = await requested('blueprint', configuration.parent); const approved = await decision('blueprint', configuration.parent, pending);
  await store.publications.assertUse('blueprint', blueprint.id, configuration.parent.version, approved.id, actor(), bearer);
  const assigned = await store.child('blueprint', blueprint.id, etag('blueprint', configuration.parent), { target_type: 'device', target_id: 'owned-device', ...confirmation }, actor(), bearer, 'assigned');
  await assert.rejects(store.publications.assertUse('blueprint', blueprint.id, assigned.parent.version, approved.id, actor(), bearer), { status: 409 });
  await assert.rejects(decision('blueprint', assigned.parent, pending), { status: 412 });
});
test('review decisions use exact resource and request versions; concurrent decisions have one winner and terminal denial cannot revive', async () => {
  const row = await draft(); const pending = await requested('policy', row);
  const results = await Promise.allSettled([decision('policy', row, pending), decision('policy', row, pending, 'denied')]);
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 1); assert.equal(results.find(result => result.status === 'rejected').reason.status, 412);
  const terminal = results.find(result => result.status === 'fulfilled').value;
  await assert.rejects(decision('policy', row, terminal), { status: 409 });
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM policy_publication_audit')).rows[0].count, 2);
});
test('reviewer withdrawal immediately fences an approved configuration without changing or deleting its historical evidence', async () => {
  const row = await draft(); const approved = await decision('policy', row, await requested('policy', row)); const active = await activate(row, approved);
  const withdrawn = await decision('policy', active, approved, 'withdrawn'); assert.equal(withdrawn.state, 'withdrawn');
  await assert.rejects(store.publications.assertUse('policy', row.id, active.version, approved.id, actor(), bearer), { status: 409 });
  assert.equal((await pool.query('SELECT state FROM policy_publications')).rows[0].state, 'withdrawn');
});
test('removed and reissued reviewer or requester authority cannot resurrect an earlier publication', async () => {
  for (const [person, duty] of [[reviewerId, 'reviewRevision'], [managerId, 'requestRevision']]) {
    const row = await draft(); const approved = await decision('policy', row, await requested('policy', row));
    sourceRows.get(person)[duty] = null; await assert.rejects(activate(row, approved), { status: 409 });
    sourceRows.get(person)[duty] = randomUUID().replaceAll('-', '').repeat(2); await assert.rejects(activate(row, approved), { status: 409 });
    if (person === reviewerId) sourceRows.get(person)[duty] = 'c'.repeat(64);
  }
});
test('source loss after approval DML rolls back the decision, mandatory audit and pending outbox', async () => {
  const row = await draft(); const pending = await requested('policy', row); sourceCalls = 0;
  sourceHook = async count => { if (count === 3) sourceRows.get(reviewerId).reviewRevision = null; };
  await assert.rejects(decision('policy', row, pending), { status: 409 });
  assert.equal((await pool.query('SELECT state FROM policy_publications')).rows[0].state, 'pending');
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM policy_publication_audit')).rows[0].count, 1);
});
test('publication audit failure cannot create an approval or hide a lost original operator behind a successful write', async () => {
  const row = await draft(); const pending = await requested('policy', row);
  await pool.query('ALTER TABLE policy_publication_audit RENAME TO owned_missing_publication_audit');
  try { await assert.rejects(decision('policy', row, pending), { status: 503 }); }
  finally { await pool.query('ALTER TABLE owned_missing_publication_audit RENAME TO policy_publication_audit'); }
  assert.equal((await pool.query('SELECT state FROM policy_publications')).rows[0].state, 'pending');
  authorityCalls = 0; authorityHook = async count => { if (count === 5) throw Object.assign(new Error('Owned original reviewer lost'), { status: 401 }); };
  await assert.rejects(decision('policy', row, pending), { status: 401 });
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM policy_publication_outbox')).rows[0].count, 1);
});
test('raw SQL cannot bypass independent activation, replace lineage or forge approval history', async () => {
  const row = await draft(); await requested('policy', row);
  for (const sql of ['UPDATE policy_publication_heads SET configuration_version=99', 'DELETE FROM policy_publication_heads', 'DELETE FROM policy_publication_audit', 'DELETE FROM policy_publication_outbox']) await assert.rejects(pool.query(sql), error => error.code === '42501');
  const client = await pool.connect();
  try {
    await client.query('BEGIN'); await store.proof(client, context(actor(), 'policies.deploy', 'policy', row.id, row.version, 'activated', confirmation.reason));
    await assert.rejects(client.query("UPDATE policies SET status='active' WHERE id=$1", [row.id]), error => error.constraint === 'policy_publication_required');
  } finally { await client.query('ROLLBACK'); client.release(); }
});
test('migration replay retains approved evidence and never resets a content generation or grants a reviewer', async () => {
  const row = await draft(); const approved = await decision('policy', row, await requested('policy', row));
  const before = (await pool.query('SELECT * FROM policy_publications')).rows;
  for (const file of ['018_policy_configuration.sql', '019_policy_publication.sql']) await pool.query(fs.readFileSync(path.join(__dirname, '../db/migrations', file), 'utf8'));
  assert.deepEqual((await pool.query('SELECT * FROM policy_publications')).rows, before); assert.equal((await activate(row, approved)).status, 'active');
});
test('known approval expiry after the last source/actor check is rejected at the actual deferred activation commit', async () => {
  const row = await draft(); const approved = await decision('policy', row, await requested('policy', row));
  await pool.query('CREATE TABLE owned_publication_clock(seconds integer NOT NULL);INSERT INTO owned_publication_clock VALUES(0)');
  await pool.query("CREATE OR REPLACE FUNCTION policy_configuration_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+seconds*interval '1 second' FROM owned_publication_clock; $$");
  const fresh = actor(); fresh.auth_time += 4; fresh.mfa_authorization.authTime = fresh.auth_time; authorityCalls = 0;
  authorityHook = async count => { if (count === 3) await pool.query('UPDATE owned_publication_clock SET seconds=301'); };
  try {
    await assert.rejects(activate(row, approved, fresh), { status: 409 });
    assert.equal((await pool.query('SELECT status FROM policies')).rows[0].status, 'draft');
  } finally { await pool.query("CREATE OR REPLACE FUNCTION policy_configuration_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp(); $$;DROP TABLE owned_publication_clock"); }
});
test('legacy active records keep their observed state but cannot manufacture publication provenance or independent approval',async()=>{
 const legacy=schema+'_old';await administration.query(`CREATE SCHEMA ${legacy}`);const client=await pool.connect();const id=randomUUID();
 try{await client.query('BEGIN');await client.query(`SET LOCAL search_path=${legacy},public`);
 for(const file of ['001_policies.sql','003_blueprints.sql'])await client.query(fs.readFileSync(path.join(__dirname,'../db/migrations',file),'utf8'));
 await client.query("INSERT INTO policies(id,name,type,platform,version,status,created_by) VALUES($1,'Observed unverified publication','security','all',8,'active','unverified-legacy-origin')",[id]);
 for(const file of ['018_policy_configuration.sql','019_policy_publication.sql'])await client.query(fs.readFileSync(path.join(__dirname,'../db/migrations',file),'utf8'));
 assert.deepEqual((await client.query('SELECT version,status FROM policies')).rows[0],{version:8,status:'active'});assert.deepEqual((await client.query('SELECT configuration_version,verified_origin FROM policy_publication_heads')).rows[0],{configuration_version:8,verified_origin:false});
 assert.equal((await client.query('SELECT policy_publication_independent($1,$2,$3) AS allowed',['policy',id,reviewerId])).rows[0].allowed,false);assert.equal((await client.query('SELECT count(*)::int AS count FROM policy_publications')).rows[0].count,0);
 }finally{await client.query('ROLLBACK');client.release();await administration.query(`DROP SCHEMA ${legacy} CASCADE`);}
});
test('one live request or approval per content generation prevents parallel votes and an old positive bypassing a newer denial',async()=>{
 const row=await draft();const pending=await requested('policy',row);await assert.rejects(requested('policy',row,otherId),{status:409});
 const approved=await decision('policy',row,pending);await assert.rejects(requested('policy',row,otherId),{status:409});
 await decision('policy',row,approved,'withdrawn');const replacement=await requested('policy',row,otherId);const denied=await decision('policy',row,replacement,'denied',actor(otherId,['policy-publication-reviewer']));assert.equal(denied.state,'denied');await assert.rejects(activate(row,approved),{status:409});
});
test('the canonical delivery frame derives one approved blueprint item and its exact device scope rather than trusting a posted payload',async()=>{
 const blueprint=await store.blueprint({name:'Owned receiver-bound blueprint',platform:'windows',...confirmation},actor(),bearer);
 const configuration=await store.child('blueprint',blueprint.id,etag('blueprint',blueprint),{config_type:'screen_lock',config_name:'Actual bound screen lock',payload:{minutes:5},...confirmation},actor(),bearer,'configuration_added');
 const assigned=await store.child('blueprint',blueprint.id,etag('blueprint',configuration.parent),{target_type:'device',target_id:'owned-target',...confirmation},actor(),bearer,'assigned');const approved=await decision('blueprint',assigned.parent,await requested('blueprint',assigned.parent));
 const request={reference:{resourceKind:'blueprint',resourceId:blueprint.id,resourceVersion:assigned.parent.version,publicationId:approved.id,configurationId:configuration.row.id},deviceId:'owned-target',platform:'windows',operationId:randomUUID()};
 const frame=await store.publications.deliveryFrame(request,actor(),bearer);assert.deepEqual(frame.payload.settings,{minutes:5});assert.equal(frame.payload.configurationId,configuration.row.id);assert.equal(frame.operatorUserId,managerId);assert.equal(frame.configurationHash,approved.configurationHash);
 const hash=(await pool.query("SELECT encode(sha256(convert_to($1::jsonb::text,'UTF8')),'hex') AS hash",[JSON.stringify(frame.payload)])).rows[0].hash;assert.equal(frame.payloadHash,hash);
 await assert.rejects(store.publications.deliveryFrame({...request,payload:{arbitrary:true}},actor(),bearer),{status:400});await assert.rejects(store.publications.deliveryFrame({...request,deviceId:'unassigned-target'},actor(),bearer),{status:409});
 await assert.rejects(store.publications.deliveryFrame({...request,platform:'linux'},actor(),bearer),{status:409});await assert.rejects(store.publications.deliveryFrame(request,reviewer(),bearer),{status:403});
});
test('GPO delivery frames preserve reviewed content generation across activation but require the exact active version and enrolled-device platform',async()=>{
 const row=await store.create({name:'Owned receiver-bound GPO',type:'gpo',settings:{configuration:{firewall:true},platforms:['windows'],gpoType:'security'},...confirmation},actor(),bearer);
 const target=await store.child('policy',row.id,etag('policy',row),{targetType:'device',targetId:'owned-gpo-target',...confirmation},actor(),bearer,'assigned');const approved=await decision('policy',target.parent,await requested('policy',target.parent));const active=await activate(target.parent,approved);
 const request={reference:{resourceKind:'policy',resourceId:row.id,resourceVersion:active.version,publicationId:approved.id,configurationId:null},deviceId:'owned-gpo-target',platform:'windows',operationId:randomUUID()};
 const frame=await store.publications.deliveryFrame(request,actor(),bearer);assert.equal(frame.configurationVersion,target.parent.version);assert.equal(frame.payload.configurationVersion,active.version);assert.deepEqual(frame.payload.settings,{firewall:true});
 await assert.rejects(store.publications.deliveryFrame({...request,reference:{...request.reference,resourceVersion:target.parent.version}},actor(),bearer),{status:412});
 await decision('policy',active,approved,'withdrawn');await assert.rejects(store.publications.deliveryFrame(request,actor(),bearer),{status:409});
});
