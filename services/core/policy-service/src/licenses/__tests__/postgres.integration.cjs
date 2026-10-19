'use strict';

const { test, before, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { randomUUID } = require('crypto');
const { Pool } = require('pg');
const { LicenseAllocator } = require('../LicenseAllocator');
const { userId, principal } = require('../../__tests__/fixtures/licenseIdentities.cjs');

const connectionString = process.env.LICENSE_TEST_DATABASE_URL;
if (!connectionString) throw new Error('LICENSE_TEST_DATABASE_URL is required for real PostgreSQL integration tests');
const schema = `license_test_${randomUUID().replaceAll('-', '')}`;
const administration = new Pool({ connectionString, max: 1 });
let pool;
let allocator;
const source = { user: async userId => ({ schemaVersion: 1, userId, revision: '1', enabled: true, deleted: false }) };
test('the actual service migration runner fences unobserved legacy groups, preserves direct overlap and never restamps them on replay',async()=>{
 const legacySchema='legacy_lease_'+randomUUID().replaceAll('-','');await administration.query('CREATE SCHEMA '+legacySchema);const legacy=new Pool({connectionString,max:4,options:`-c search_path=${legacySchema},public`});const previousUrl=process.env.DATABASE_URL;
 const url=new URL(connectionString);url.searchParams.set('options',`-c search_path=${legacySchema},public`);process.env.DATABASE_URL=url.toString();const database=require('../../db/postgres');
 try{
 for(const name of fs.readdirSync(path.join(__dirname,'../../db/migrations')).filter(name=>/^(00[4-9]|01[0-5])_/.test(name)).sort())await legacy.query(fs.readFileSync(path.join(__dirname,'../../db/migrations',name),'utf8'));
 const licenseId=(await legacy.query("INSERT INTO license_catalog(name,total_seats) VALUES('Owned pre-lease upgrade',3) RETURNING id")).rows[0].id;const groupId=randomUUID();const only=randomUUID();const overlap=randomUUID();const base=new Date(Date.now()+3600000).toISOString();
 for(const userId of [only,overlap])await legacy.query('INSERT INTO license_subjects(user_id,directory_revision,directory_enabled,directory_deleted) VALUES($1,1,true,false)',[userId]);
 await legacy.query("INSERT INTO license_group_rules(license_id,group_id,configured_by) VALUES($1,$2,'owned-pre-lease')",[licenseId,groupId]);
 for(const userId of [only,overlap])await legacy.query("INSERT INTO license_assignment_sources(license_id,user_id,source_type,source_id,assigned_by) VALUES($1,$2,'group',$3,'owned-pre-lease')",[licenseId,userId,groupId]);
 await legacy.query("INSERT INTO license_assignment_sources(license_id,user_id,source_type,source_id,assigned_by,expires_at) VALUES($1,$2,'direct','direct','owned-pre-lease',$3)",[licenseId,overlap,base]);
 for(const userId of [only,overlap])await legacy.query("INSERT INTO license_assignments(license_id,assignee_type,assignee_id) VALUES($1,'user',$2)",[licenseId,userId]);
 const origin=(await legacy.query('SELECT * FROM license_grants ORDER BY id')).rows;
 await legacy.query("CREATE FUNCTION reject_owned_upgrade_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='unobserved-group-projection-fenced' THEN RAISE EXCEPTION 'Owned upgrade audit unavailable';END IF;RETURN NEW;END;$$;CREATE TRIGGER reject_owned_upgrade_audit BEFORE INSERT ON license_audit_events FOR EACH ROW EXECUTE FUNCTION reject_owned_upgrade_audit()");
 await assert.rejects(database.runMigrations(),/Owned upgrade audit unavailable/);assert.equal((await legacy.query('SELECT count(*)::int AS count FROM license_assignments')).rows[0].count,2);assert.equal((await legacy.query("SELECT to_regclass('license_group_observations') AS relation")).rows[0].relation,null);
 await legacy.query('DROP TRIGGER reject_owned_upgrade_audit ON license_audit_events;DROP FUNCTION reject_owned_upgrade_audit()');
 await database.runMigrations();const projected=(await legacy.query('SELECT assignee_id,expires_at FROM license_assignments')).rows;assert.equal(projected.length,1);assert.equal(projected[0].assignee_id,overlap);assert.equal(projected[0].expires_at.toISOString(),base);
 assert.equal((await legacy.query('SELECT count(*)::int AS count FROM license_assignment_sources')).rows[0].count,3);assert.deepEqual((await legacy.query('SELECT * FROM license_grants ORDER BY id')).rows,origin);assert.equal((await legacy.query('SELECT count(*)::int AS count FROM license_group_observations')).rows[0].count,0);
 await database.runMigrations();assert.equal((await legacy.query("SELECT count(*)::int AS count FROM license_audit_events WHERE action='unobserved-group-projection-fenced'")).rows[0].count,2);
 const{groupSnapshot}=require('../../../../../../scripts/lib/group-license-snapshot-fixture.cjs');const source={snapshot:async()=>groupSnapshot({groupId,memberIds:[only,overlap]})};const allocator=new LicenseAllocator({query:(...args)=>legacy.query(...args),getClient:()=>legacy.connect()},{source});
 new(require('../GroupLicenseAllocator').GroupLicenseAllocator)({allocator,source});await allocator.assign(licenseId,{assignee_type:'group',assignee_id:groupId},'owned-upgrade',{});const observed=(await legacy.query('SELECT * FROM license_group_observations')).rows;
 await database.runMigrations();assert.deepEqual((await legacy.query('SELECT * FROM license_group_observations')).rows,observed);
 const projections=(await legacy.query('SELECT * FROM license_assignments ORDER BY id')).rows;
 await database.runMigrations();assert.deepEqual((await legacy.query('SELECT * FROM license_group_observations')).rows,observed);assert.deepEqual((await legacy.query('SELECT * FROM license_assignments ORDER BY id')).rows,projections);
 assert.equal((await legacy.query('SELECT count(*)::int AS count FROM license_assignments WHERE license_id=$1 AND (expires_at IS NULL OR expires_at>$2)',[licenseId,new Date(observed[0].valid_until.getTime()+1)])).rows[0].count,1);
 }finally{await database.shutdown();if(previousUrl===undefined)delete process.env.DATABASE_URL;else process.env.DATABASE_URL=previousUrl;await legacy.end();await administration.query('DROP SCHEMA '+legacySchema+' CASCADE');}
});

before(async () => {
  await administration.query(`CREATE SCHEMA ${schema}`);
  pool = new Pool({ connectionString, max: 16, options: `-c search_path=${schema},public` });
  for (const migration of fs.readdirSync(path.join(__dirname,'../../db/migrations')).filter(name=>/^(00[4-9]|01[0-7]|02[0-2])_.*\.sql$/.test(name)).sort()) {
    await pool.query(fs.readFileSync(path.join(__dirname, '../../db/migrations', migration), 'utf8'));
  }
  allocator = new LicenseAllocator({ query: (sql, params) => pool.query(sql, params), getClient: () => pool.connect() }, { source });
});

beforeEach(async () => {
  await pool.query('CREATE OR REPLACE FUNCTION license_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp(); $$');
  await pool.query('TRUNCATE license_assignments, license_requests, license_catalog, license_subjects, license_audit_events, license_assignment_sources, license_group_rules CASCADE');
});

after(async () => {
  if (pool) await pool.end();
  await administration.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
  await administration.end();
});

async function license(seats = 1, autoApprove = false) {
  return (await pool.query('INSERT INTO license_catalog (name, total_seats, auto_approve) VALUES ($1,$2,$3) RETURNING *', ['Office', seats, autoApprove])).rows[0];
}

function assignee(name) { return { assignee_type: 'user', assignee_id: userId(name) }; }
function requestFor(name, extra = {}) { return { requester_id: userId(name), requester_name: name, ...assignee(name), ...extra, ...(extra.assignee_id ? { assignee_id: userId(extra.assignee_id) } : {}) }; }
async function requestLicense(licenseId, request) { return allocator.request(licenseId, request, { principal: principal(request.requester_name) }); }
async function reviewLicense(requestId, actor, decision) { return allocator.review(requestId, userId(actor), decision, { principal: principal(actor) }); }

async function seats(licenseId) {
  return (await pool.query(`SELECT total_seats, used_seats, (SELECT COUNT(*)::int FROM license_assignments
    WHERE license_id = license_catalog.id AND (expires_at IS NULL OR expires_at > clock_timestamp())) AS active
    FROM license_catalog WHERE id = $1`, [licenseId])).rows[0];
}

test('lineage migration observes legacy grants without inventing authority and refuses orphaned or inconsistent group sources', async () => {
  const legacySchema = 'legacy_grants_' + randomUUID().replaceAll('-', '');
  await administration.query(`CREATE SCHEMA ${legacySchema}`);
  const legacy = new Pool({ connectionString, max: 1, options: `-c search_path=${legacySchema},public` });
  try {
    for (const migration of ['004_licenses.sql', '005_license_allocation.sql', '006_group_license_sources.sql', '007_license_principal_binding.sql', '008_user_eligibility.sql', '009_license_fulfillment.sql']) await legacy.query(fs.readFileSync(path.join(__dirname, '../../db/migrations', migration), 'utf8'));
    const poolId = (await legacy.query("INSERT INTO license_catalog(name,total_seats) VALUES('Legacy observed pool',3) RETURNING id")).rows[0].id;
    await legacy.query("INSERT INTO license_assignment_sources(license_id,user_id,source_type,source_id,assigned_by) VALUES($1,'legacy-user','direct','direct','unknown-original-actor'),($1,'legacy-user','group','legacy-group','unknown-original-actor')", [poolId]);
    const migration = fs.readFileSync(path.join(__dirname, '../../db/migrations/010_license_grant_lineage.sql'), 'utf8');
    await assert.rejects(legacy.query(migration), error => error.code === '23514' && error.message.includes('Unresolved group'));
    await legacy.query("INSERT INTO license_group_rules(license_id,group_id,configured_by,enabled) VALUES($1,'legacy-group','unknown-original-actor',false)", [poolId]);
    await assert.rejects(legacy.query(migration), error => error.code === '23514' && error.message.includes('Inconsistent group'));
    await legacy.query("DELETE FROM license_assignment_sources WHERE source_type='group'");
    await legacy.query(migration);
    const before = (await legacy.query('SELECT * FROM license_grants ORDER BY id')).rows;
    assert.equal(before.length, 2); assert.ok(before.every(row => row.origin === 'observed'));
    const evidence = (await legacy.query('SELECT * FROM license_grant_events')).rows;
    assert.ok(evidence.every(row => row.version === '1' && row.actor_user_id === null && row.actor_issuer === null && row.actor_subject === null));
    assert.equal(evidence.filter(row => row.state === 'revoked').length, 1);
    await legacy.query(migration); assert.deepEqual((await legacy.query('SELECT * FROM license_grants ORDER BY id')).rows, before);
    const oldCanonical = randomUUID();
    await legacy.query('INSERT INTO license_subjects(user_id,directory_revision,directory_enabled,directory_deleted) VALUES($1,7,true,false)', [oldCanonical]);
    await legacy.query("INSERT INTO license_assignment_sources(license_id,user_id,source_type,source_id,assigned_by) VALUES($1,$2,'direct','direct','old-canonical-allocator')", [poolId, oldCanonical]);
    await legacy.query(fs.readFileSync(path.join(__dirname, '../../db/migrations/011_license_reviews.sql'), 'utf8'));
    assert.ok((await legacy.query('SELECT eligibility_revision FROM license_grants')).rows.every(row => row.eligibility_revision === null));
    await assert.rejects(legacy.query('UPDATE license_grants SET eligibility_revision=7 WHERE recipient_id=$1', [oldCanonical]), error => error.code === '42501');
    const newCanonical = randomUUID();
    await legacy.query('INSERT INTO license_subjects(user_id,directory_revision,directory_enabled,directory_deleted) VALUES($1,9,true,false)', [newCanonical]);
    await legacy.query("INSERT INTO license_assignment_sources(license_id,user_id,source_type,source_id,assigned_by) VALUES($1,$2,'direct','direct','new-canonical-allocator')", [poolId, newCanonical]);
    assert.equal((await legacy.query('SELECT eligibility_revision FROM license_grants WHERE recipient_id=$1', [newCanonical])).rows[0].eligibility_revision, '9');
  } finally { await legacy.end(); await administration.query(`DROP SCHEMA ${legacySchema} CASCADE`); }
});

test('concurrent callers cannot overbook a pool, even with different actors and beneficiaries', async () => {
  const product = await license(5);
  const results = await Promise.allSettled(Array.from({ length: 24 }, (_, index) => allocator.assign(product.id, assignee(`user-${index}`), `manager-${index}`)));
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 5);
  for (const rejected of results.filter(result => result.status === 'rejected')) assert.equal(rejected.reason.status, 409);
  assert.deepEqual(await seats(product.id), { total_seats: 5, used_seats: 5, active: 5 });
  assert.equal((await pool.query("SELECT COUNT(*)::int AS count FROM license_audit_events WHERE action='assigned'")).rows[0].count, 5);
});

test('repeated automatic requests consume one seat and return the same decision', async () => {
  const product = await license(2, true);
  const settled = await Promise.allSettled(Array.from({ length: 12 }, () => requestLicense(product.id, requestFor('alice'))));
  assert.ok(settled.every(result => result.status === 'fulfilled'), settled.find(result => result.status === 'rejected')?.reason?.message);
  const results = settled.map(result => result.value);
  assert.equal(new Set(results.map(result => result.record.id)).size, 1);
  assert.equal(results.filter(result => result.created).length, 1);
  assert.equal(results[0].record.status, 'approved');
  assert.equal((await seats(product.id)).active, 1);
  assert.equal((await pool.query('SELECT COUNT(*)::int AS count FROM license_requests')).rows[0].count, 1);
});

test('duplicate pending requests and simultaneous approval/denial produce a single decision', async () => {
  const product = await license();
  const settled = await Promise.allSettled(Array.from({ length: 8 }, () => requestLicense(product.id, requestFor('alice'))));
  assert.ok(settled.every(result => result.status === 'fulfilled'), settled.find(result => result.status === 'rejected')?.reason?.message);
  const requests = settled.map(result => result.value);
  assert.equal(new Set(requests.map(result => result.record.id)).size, 1);
  const outcomes = await Promise.allSettled([
    reviewLicense(requests[0].record.id, 'reviewer-one', 'approved'),
    reviewLicense(requests[0].record.id, 'reviewer-two', 'denied'),
  ]);
  assert.equal(outcomes.filter(result => result.status === 'fulfilled').length, 1);
  assert.equal(outcomes.find(result => result.status === 'rejected').reason.status, 409);
  const final = (await pool.query('SELECT * FROM license_requests')).rows[0];
  assert.equal((await seats(product.id)).active, final.status === 'approved' ? 1 : 0);
});

test('manual assignment followed by approval does not consume the same seat twice', async () => {
  const product = await license();
  const request = await requestLicense(product.id, requestFor('alice'));
  await allocator.assign(product.id, assignee('alice'), 'manager');
  assert.equal((await reviewLicense(request.record.id, 'reviewer', 'approved')).status, 'approved');
  assert.equal((await seats(product.id)).active, 1);
});

test('a failure writing the audit rolls back assignments, counters, and subject creation', async () => {
  const product = await license();
  const broken = new LicenseAllocator({ query: pool.query.bind(pool), getClient: async () => {
    const client = await pool.connect();
    return { release: () => client.release(), query: (sql, parameters) => sql.startsWith('INSERT INTO license_audit_events')
      ? Promise.reject(new Error('Injected audit failure')) : client.query(sql, parameters) };
  } }, { source });
  await assert.rejects(broken.assign(product.id, assignee('alice'), 'manager'), error => error.noFallback === true);
  assert.equal((await seats(product.id)).active, 0);
  assert.equal((await seats(product.id)).used_seats, 0);
  assert.equal((await pool.query('SELECT COUNT(*)::int AS count FROM license_subjects')).rows[0].count, 0);
});

test('capacity reductions racing with assignments cannot create an overallocated catalog', async () => {
  const product = await license(2);
  await allocator.assign(product.id, assignee('first-user'), 'first-manager');
  const outcomes = await Promise.allSettled([
    allocator.assign(product.id, assignee('second-user'), 'second-manager'),
    pool.query('UPDATE license_catalog SET total_seats = 1 WHERE id = $1', [product.id]),
  ]);
  assert.equal(outcomes.filter(result => result.status === 'fulfilled').length, 1);
  const final = await seats(product.id);
  assert.ok(final.active <= final.total_seats);
  assert.equal(final.active, final.used_seats);
});

test('expired allocations release capacity and can be assigned again to the same user', async () => {
  const product = await license();
  await allocator.assign(product.id,{...assignee('alice'),expires_at:new Date(Date.now()+10000).toISOString()},'manager');
  await pool.query("CREATE OR REPLACE FUNCTION license_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+interval '11 seconds'; $$");
  await allocator.assign(product.id, assignee('alice'), 'manager');
  assert.equal((await seats(product.id)).active, 1);
  assert.equal((await pool.query("SELECT COUNT(*)::int AS count FROM license_audit_events WHERE action = 'expired'")).rows[0].count, 1);
});

test('expiry sweep releases seats across pools and is idempotent', async () => {
  for (let index = 0; index < 2; index++) {
    const product = await license();
    await allocator.assign(product.id,{...assignee(`user-${index}`),expires_at:new Date(Date.now()+10000).toISOString()},'manager');
  }
  await pool.query("CREATE OR REPLACE FUNCTION license_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+interval '11 seconds'; $$");
  assert.equal(await allocator.expireAll(), 2);
  assert.equal(await allocator.expireAll(), 0);
  assert.equal((await pool.query('SELECT SUM(used_seats)::int AS used FROM license_catalog')).rows[0].used, 0);
});

test('offboarding revokes all direct user seats, cancels pending requests, and prevents reassignment', async () => {
  const first = await license(3);
  const second = await license(3);
  const third = await license(3);
  await allocator.assign(first.id, assignee('alice'), 'manager');
  await allocator.assign(second.id, assignee('alice'), 'manager');
  await allocator.assign(first.id, assignee('bob'), 'manager');
  await requestLicense(first.id, requestFor('alice', { assignee_id: 'carol' }));
  await requestLicense(third.id, requestFor('dave', { assignee_id: 'alice' }));
  assert.deepEqual(await allocator.offboard(userId('alice'), 'administrator'), { userId: userId('alice'), assignmentsRevoked: 2, requestsCancelled: 2, localOnly: true });
  assert.equal((await seats(first.id)).used_seats, 1);
  assert.equal((await seats(second.id)).used_seats, 0);
  await assert.rejects(allocator.assign(first.id, assignee('alice'), 'manager'), error => error.status === 403);
  await assert.rejects(requestLicense(first.id, requestFor('alice')), error => error.status === 403);
  assert.deepEqual(await allocator.offboard(userId('alice'), 'administrator'), { userId: userId('alice'), assignmentsRevoked: 0, requestsCancelled: 0, localOnly: true });
});

test('an assignment racing with offboarding cannot leave a seat on a disabled user', async () => {
  const product = await license();
  const results = await Promise.allSettled([
    allocator.assign(product.id, assignee('alice'), 'manager'), allocator.offboard(userId('alice'), 'administrator'),
  ]);
  assert.equal(results[1].status, 'fulfilled');
  assert.equal((await seats(product.id)).active, 0);
  assert.equal((await pool.query('SELECT disabled FROM license_subjects WHERE user_id = $1', [userId('alice')])).rows[0].disabled, true);
});

test('a failed offboarding transaction does not publish a disabled state with unreleased seats', async () => {
  const product = await license();
  await allocator.assign(product.id, assignee('alice'), 'manager');
  const broken = new LicenseAllocator({ getClient: async () => {
    const client = await pool.connect();
    return { release: () => client.release(), query: (sql, parameters) => sql.startsWith('INSERT INTO license_audit_events')
      ? Promise.reject(new Error('Injected offboarding audit failure')) : client.query(sql, parameters) };
  } });
  await assert.rejects(broken.offboard(userId('alice'), 'administrator'));
  assert.equal((await pool.query('SELECT disabled FROM license_subjects WHERE user_id = $1', [userId('alice')])).rows[0].disabled, false);
  assert.equal((await seats(product.id)).active, 1);
});

test('self-approval is denied and the request remains pending', async () => {
  const product = await license();
  const request = await requestLicense(product.id, requestFor('alice'));
  await assert.rejects(reviewLicense(request.record.id, 'alice', 'approved'), error => error.status === 403);
  assert.equal((await pool.query('SELECT status FROM license_requests')).rows[0].status, 'pending');
});

test('request and review domain operations require a canonical enabled principal even without HTTP middleware', async () => {
  const product = await license();
  for (const identity of [undefined, { ...principal('alice'), userId: 'alice' }, { ...principal('alice'), enabled: false }, principal('different-user')]) {
    await assert.rejects(allocator.request(product.id, requestFor('alice'), { principal: identity }), error => error.status === 403);
  }
  const request = await requestLicense(product.id, requestFor('alice'));
  await assert.rejects(allocator.review(request.record.id, userId('reviewer'), 'approved'), error => error.status === 403);
  assert.equal((await pool.query('SELECT status FROM license_requests')).rows[0].status, 'pending');
});

test('revoke requires a type when user and device identifiers collide', async () => {
  const product = await license(3);
  await allocator.assign(product.id, assignee('same-id'), 'manager');
  await allocator.assign(product.id, { assignee_type: 'device', assignee_id: userId('same-id') }, 'manager');
  await assert.rejects(allocator.revoke(product.id, userId('same-id'), 'manager'), error => error.status === 409);
  await allocator.revoke(product.id, userId('same-id'), 'manager', 'user');
  assert.equal((await pool.query('SELECT assignee_type FROM license_assignments')).rows[0].assignee_type, 'device');
  assert.equal((await seats(product.id)).used_seats, 1);
});

test('license audit records cannot be updated or deleted through normal SQL writes', async () => {
  const product = await license();
  await allocator.assign(product.id, assignee('alice'), 'manager');
  await assert.rejects(pool.query("UPDATE license_audit_events SET actor = 'forged'"), error => error.code === '42501');
  await assert.rejects(pool.query('DELETE FROM license_audit_events'), error => error.code === '42501');
});

test('database capacity guards reject raw writes that bypass application checks', async () => {
  const product = await license();
  await allocator.assign(product.id,assignee('alice'),'manager');
  await assert.rejects(pool.query("INSERT INTO license_assignments (license_id, assignee_type, assignee_id) VALUES ($1,'user','bob')", [product.id]), error => error.code === '23514');
  assert.deepEqual(await seats(product.id), { total_seats: 1, used_seats: 1, active: 1 });
  await assert.rejects(pool.query("UPDATE license_assignments SET expires_at = NOW() + INTERVAL '1 hour'"), error => error.code === '42501');
});

test('the allocation migration can be reapplied without losing existing assignments or audit events', async () => {
  const product = await license();
  await allocator.assign(product.id, assignee('alice'), 'manager');
  await pool.query(fs.readFileSync(path.join(__dirname, '../../db/migrations/005_license_allocation.sql'), 'utf8'));
  assert.equal((await seats(product.id)).active, 1);
  assert.equal((await pool.query("SELECT COUNT(*)::int AS count FROM license_audit_events WHERE action='assigned'")).rows[0].count, 1);
});

test('an authorized reactivation restores eligibility without silently restoring prior licenses', async () => {
  const product = await license();
  await allocator.assign(product.id, assignee('alice'), 'manager');
  await allocator.offboard(userId('alice'), 'administrator');
  await assert.rejects(allocator.activate(userId('alice'), userId('alice')), error => error.status === 403);
  assert.deepEqual(await allocator.activate(userId('alice'), 'administrator'), { userId: userId('alice'), disabled: false, localOnly: true });
  assert.equal((await seats(product.id)).active, 0);
  await allocator.assign(product.id, assignee('alice'), 'manager');
  assert.equal((await seats(product.id)).active, 1);
});

test('a selected reconciliation candidate adopted before source lookup skips physical error DML without touching its owned mirror', async () => {
  const selectedUser = randomUUID(); const tenantId = randomUUID(); const attemptedAt = '2026-10-19T00:00:00.000Z';
  await pool.query('INSERT INTO license_subjects(user_id,directory_revision,directory_enabled,directory_deleted,directory_attempted_at,directory_error) VALUES($1,1,true,false,$2,$3)', [selectedUser, attemptedAt, 'Retained legacy observation']);
  let retained; let selected = false; let errorRows = null; let sourceCalls = 0;
  const capture = async () => (await pool.query('SELECT to_jsonb(subject) AS state FROM license_subjects subject WHERE user_id=$1', [selectedUser])).rows[0].state;
  const auditBefore = (await pool.query('SELECT count(*)::text AS count FROM license_audit_events')).rows[0].count;
  const boundaryDatabase = { getClient: () => pool.connect(), query: async (query, parameters) => {
    const result = await pool.query(query, parameters);
    if (!selected && query.includes('SELECT candidates.user_id')) {
      selected = true; assert.deepEqual(result.rows.map(row => row.user_id), [selectedUser]);
      const client = await pool.connect();
      try { await client.query('BEGIN'); await client.query('ALTER TABLE license_subjects DISABLE TRIGGER USER'); await client.query('UPDATE license_subjects SET business_tenant_id=$2 WHERE user_id=$1', [selectedUser, tenantId]); await client.query('ALTER TABLE license_subjects ENABLE TRIGGER USER'); await client.query('COMMIT'); }
      catch (error) { await client.query('ROLLBACK'); throw error; } finally { client.release(); }
      retained = await capture();
    }
    if (query.startsWith('INSERT INTO license_subjects(user_id,directory_attempted_at,directory_error)')) errorRows = result.rowCount;
    return result;
  } };
  const delayed = new LicenseAllocator(boundaryDatabase, { source: { user: async () => { sourceCalls++; throw new Error('Owned mirror reached the legacy source'); } } });
  try {
    assert.deepEqual(await delayed.users.reconcileAll('Bearer controlled-native-fixture'), [{ userId: selectedUser, error: 'Legacy license subject not found' }]);
    assert.equal(selected, true); assert.equal(sourceCalls, 0); assert.equal(errorRows, 0);
    assert.deepEqual(await capture(), retained);
    assert.equal((await pool.query('SELECT count(*)::text AS count FROM license_audit_events')).rows[0].count, auditBefore);
  } finally {
    const cleanup = await pool.connect();
    try { await cleanup.query('BEGIN'); await cleanup.query('ALTER TABLE license_subjects DISABLE TRIGGER USER'); await cleanup.query('UPDATE license_subjects SET business_tenant_id=NULL WHERE user_id=$1', [selectedUser]); await cleanup.query('ALTER TABLE license_subjects ENABLE TRIGGER USER'); await cleanup.query('COMMIT'); }
    catch (error) { await cleanup.query('ROLLBACK'); throw error; } finally { cleanup.release(); }
  }
});
