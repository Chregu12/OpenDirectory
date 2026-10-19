'use strict';

const { test, before, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const fs = require('node:fs'); const path = require('node:path');
const { Pool } = require('pg');
const { LicenseAllocator } = require('../LicenseAllocator');
const { GroupLicenseAllocator } = require('../GroupLicenseAllocator');
const { LicenseReviews, policyTag, reviewTag } = require('../LicenseReviews');
const { principalContext } = require('../LicensePrincipal');
const{groupSnapshot}=require('../../../../../../scripts/lib/group-license-snapshot-fixture.cjs');
const schema = 'license_reviews_' + randomUUID().replaceAll('-', '');
const administration = new Pool({ connectionString: process.env.LICENSE_TEST_DATABASE_URL, max: 1 });
let pool; let allocator; let reviews; let groups; let fault; let validations; let unavailable;
const people = new Map(); const directoryGroups = new Map();
function actor(role) {
  const userId = randomUUID(); const authTime = Math.floor(Date.now() / 1000);
  const principal = { userId, issuer: 'https://license-reviews.test', subject: userId, enabled: true };
  const user = { iss: principal.issuer, sub: userId, actor_type: 'user', roles: [role], identity_authorization: { userId, revision: '1', linkRevision: '1', rolesRevision: 'a'.repeat(64) },
    auth_time: authTime, amr: ['pwd', 'otp'], mfa_authorization: { schemaVersion: 1, userId, revision: '1', authTime, methods: ['pwd', 'otp'] } };
  people.set(userId, { role, enabled: true }); return { user, principal, authorization: 'Bearer ' + userId };
}
let manager; let configurator; let voter; let beneficiary; let reader;
const source = {
  user: async userId => ({ schemaVersion: 1, userId, revision: people.get(userId)?.revision || '1', enabled: people.get(userId)?.enabled === true, deleted: !people.has(userId) }),
  reviewer: async userId => ({ canReview: !unavailable && people.get(userId)?.enabled && ['license-reviewer', 'admin'].includes(people.get(userId)?.role) }),
  snapshot: async (groupId, authorization) => {
    if (unavailable) throw Object.assign(new Error('Owned directory outage'), { status: 503 });
    const group = directoryGroups.get(groupId);
    return groupSnapshot({groupId,name:'Owned license team',revision:group.revision,memberIds:group.members,unresolvedMemberIds:group.unresolved||[],viewerUserId:authorization.slice(7),viewerEnabled:true},{revisions:Object.fromEntries([...people].map(([userId,person])=>[userId,person.revision||'1']))});
  },
};
before(async () => {
  await administration.query('CREATE SCHEMA ' + schema);
  pool = new Pool({ connectionString: process.env.LICENSE_TEST_DATABASE_URL, max: 12, options: `-c search_path=${schema},public` });
  for (const name of fs.readdirSync(path.join(__dirname, '../../db/migrations')).filter(name => /^(00[4-9]|01[0-7]|02[0-2])_.*\.sql$/.test(name)).sort()) await pool.query(fs.readFileSync(path.join(__dirname, '../../db/migrations', name), 'utf8'));
  allocator = new LicenseAllocator({ query: (...args) => pool.query(...args), getClient: () => pool.connect() }, { source });
  groups = new GroupLicenseAllocator({ allocator, source });
  reviews = new LicenseReviews(allocator, { source, revalidate: async () => { validations++; if (fault) await fault(validations); } });
});
beforeEach(async () => {
  await pool.query('TRUNCATE license_review_audit,license_review_leases,license_review_policies,license_grant_events,license_grants,license_catalog,license_subjects,license_requests,license_audit_events CASCADE');
  await clock(0); people.clear(); directoryGroups.clear(); fault = null; validations = 0; unavailable = false;
  manager = actor('license-manager'); configurator = actor('license-review-administrator'); voter = actor('license-reviewer'); beneficiary = actor('user'); reader = actor('license-review-reader');
});
after(async () => { await pool.end(); await administration.query('DROP SCHEMA ' + schema + ' CASCADE'); await administration.end(); });
async function clock(seconds) { await pool.query(`CREATE OR REPLACE FUNCTION license_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+interval '${Number(seconds)} seconds'; $$`); }
async function product() { return (await pool.query("INSERT INTO license_catalog(name,total_seats) VALUES('Owned reviewed license',10) RETURNING *")).rows[0]; }
async function direct(license, recipient = beneficiary) {
  return principalContext.run(manager.principal, () => allocator.assign(license.id, { assignee_type: 'user', assignee_id: recipient.principal.userId }, manager.principal.userId, manager));
}
async function groupGrant(license, members = [beneficiary.principal.userId]) {
  const id = randomUUID(); directoryGroups.set(id, { members, revision: '1' });
  const result = await principalContext.run(manager.principal, () => allocator.assign(license.id, { assignee_type: 'group', assignee_id: id }, manager.principal.userId, manager));
  return result.rule;
}
async function configure(license, extra = {}) {
  return reviews.create({ licenseId: license.id, intervalSeconds: 3600, windowSeconds: 60, reviewerUserIds: [voter.principal.userId], reason: 'Independent recurring recipient certification', acknowledgeDeadlines: true, ...extra }, configurator.user, configurator.principal, configurator.authorization);
}
async function queue(who = voter) { return (await reviews.self(who.user, who.principal)).reviews; }
async function decision(row, decision = 'retain', who = voter) {
  return reviews.decide(row.id, reviewTag(row), { decision, reason: 'Independent current source certification', acknowledgeScope: true }, who.user, who.principal, who.authorization);
}
async function effective(license) { return (await pool.query('SELECT * FROM license_assignments WHERE license_id=$1 AND (expires_at IS NULL OR expires_at>license_now())', [license.id])).rows; }

test('configuration caps existing projections without rewriting base expiry and captures later grant incarnations', async () => {
  const license = await product(); await direct(license); const policy = await configure(license); const [row] = await queue();
  assert.equal(row.state, 'pending'); assert.equal(row.baseExpiresAt, null); assert.equal(row.policyId, policy.id);
  assert.ok((await effective(license))[0].expires_at); assert.equal((await pool.query('SELECT expires_at FROM license_assignment_sources')).rows[0].expires_at, null);
  await direct(license, actor('user')); assert.equal((await queue()).length, 2);
  assert.equal((await effective(license)).length, 2);
});
test('SQL source insertion waiting behind configuration captures the newly committed policy instead of escaping its lease', async () => {
  const license = await product(); await direct(license); const newcomer = actor('user'); let entered = false; let resume; let configuration; let insertion;
  const release = new Promise(resolve => { resume = resolve; });
  fault = async count => { if (count === 1) { entered = true; await release; } };
  try {
    configuration = configure(license); configuration.catch(() => {});
    for (let attempt = 0; attempt < 200 && !entered; attempt++) await new Promise(resolve => setTimeout(resolve, 10));
    assert.equal(entered, true);
    insertion = pool.query("INSERT INTO license_assignment_sources(license_id,user_id,source_type,source_id,assigned_by) VALUES($1,$2,'direct','direct','owned-SQL-source') RETURNING grant_id", [license.id, newcomer.principal.userId]); insertion.catch(() => {});
    let waiting = false;
    for (let attempt = 0; attempt < 200; attempt++) {
      waiting = (await pool.query("SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'INSERT INTO license_assignment_sources(license_id,user_id,source_type,source_id,assigned_by) VALUES%'")).rows.length > 0;
      if (waiting) break; await new Promise(resolve => setTimeout(resolve, 10));
    }
    assert.equal(waiting, true); resume(); const policy = await configuration; const result = await insertion;
    const lease = (await pool.query('SELECT * FROM license_review_leases WHERE grant_id=$1', [result.rows[0].grant_id])).rows[0];
    assert.equal(lease.policy_id, policy.id); assert.equal(lease.state, 'pending');
  } finally { resume(); if (configuration) await configuration.catch(() => {}); if (insertion) await insertion.catch(() => {}); }
});
test('retention advances only the cycle, supports recurrence and never creates a new source grant', async () => {
  const license = await product(); await direct(license); await configure(license); const [before] = await queue();
  const retained = await decision(before); assert.equal(retained.state, 'scheduled'); assert.equal(retained.cycle, '2'); assert.equal(retained.grantId, before.grantId); assert.equal(retained.baseExpiresAt, null);
  await clock(3601); const [due] = await queue(); assert.equal(due.state, 'pending'); assert.equal((await effective(license)).length, 1);
  const next = await decision(due); assert.equal(next.cycle, '3'); assert.equal(next.state, 'scheduled');
  assert.equal((await pool.query('SELECT COUNT(*)::int AS count FROM license_grants')).rows[0].count, 1);
});
test('retention never extends a finite base license even when its next review would be much later', async () => {
  const license = await product(); const base = new Date(Date.now() + 300000).toISOString();
  await allocator.assign(license.id, { assignee_type: 'user', assignee_id: beneficiary.principal.userId, expires_at: base }, manager.principal.userId, manager);
  await configure(license); const [row] = await queue(); const retained = await decision(row);
  assert.equal(retained.baseExpiresAt, base); assert.equal((await effective(license))[0].expires_at.toISOString(), base);
  assert.equal((await pool.query('SELECT expires_at FROM license_assignment_sources')).rows[0].expires_at.toISOString(), base);
  await clock(301); assert.equal((await effective(license)).length, 0); assert.equal((await queue())[0].state, 'obsolete');
});
test('a missed beneficiary disable/reactivate generation cannot be recertified as the same direct grant', async () => {
  const license = await product(); await direct(license); await configure(license); const [before] = await queue();
  people.get(beneficiary.principal.userId).revision = '3';
  await assert.rejects(decision(before), error => error.status === 409 && error.message === 'license_source_eligibility_changed');
  assert.equal((await queue())[0].version, before.version);
  await allocator.users.reconcileSnapshot(await source.user(beneficiary.principal.userId), manager.principal.userId);
  assert.equal((await queue())[0].state, 'obsolete');
  await allocator.revoke(license.id, beneficiary.principal.userId, manager.principal.userId, 'user'); await direct(license);
  const current = (await queue()).find(row => row.state === 'pending'); assert.notEqual(current.grantId, before.grantId); assert.equal((await decision(current)).state, 'scheduled');
});
test('migration reapplication preserves review identity, accepted cutoff, source version and projection', async () => {
  const license = await product(); await direct(license); const policy = await configure(license); const [before] = await queue(); const assignments = await effective(license);
  await pool.query(fs.readFileSync(path.join(__dirname, '../../db/migrations/011_license_reviews.sql'), 'utf8'));
  await pool.query(fs.readFileSync(path.join(__dirname, '../../db/migrations/016_group_directory_leases.sql'), 'utf8'));
  await pool.query(fs.readFileSync(path.join(__dirname, '../../db/migrations/017_group_source_consents.sql'), 'utf8'));
  assert.deepEqual((await reviews.policy(license.id, configurator.user, configurator.principal)).policy, policy);
  assert.deepEqual((await queue())[0], before); assert.deepEqual(await effective(license), assignments);
});
test('competing reviewers cannot advance the same captured cycle twice', async () => {
  const license = await product(); await direct(license); await configure(license); const [row] = await queue();
  const results = await Promise.allSettled([decision(row), decision(row)]);
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
  assert.equal(results.find(result => result.status === 'rejected').reason.status, 412);
  const evidence = (await pool.query("SELECT * FROM license_review_audit WHERE action='retain'")).rows;
  assert.equal(evidence.length, 1); assert.equal(evidence[0].actor.reviewedSourceVersion, row.sourceVersion); assert.equal(evidence[0].actor.reviewedPolicyVersion, row.policyVersion);
});
test('review audit failure rolls back the cycle and capped projection instead of confirming an unrecorded vote', async () => {
  const license = await product(); await direct(license); await configure(license); const [before] = await queue(); const assignments = await effective(license);
  await pool.query("CREATE FUNCTION reject_review_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='retain' THEN RAISE EXCEPTION 'Owned failed review audit'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_review_audit BEFORE INSERT ON license_review_audit FOR EACH ROW EXECUTE FUNCTION reject_review_audit()");
  try { await assert.rejects(decision(before), error => error.code === 'P0001'); }
  finally { await pool.query('DROP TRIGGER reject_review_audit ON license_review_audit; DROP FUNCTION reject_review_audit()'); }
  assert.deepEqual((await queue())[0], before); assert.deepEqual(await effective(license), assignments);
});
test('raw projection inserts cannot bypass a reviewed source expiry or introduce a device into its human pool', async () => {
  const license = await product(); await direct(license); await configure(license);
  await pool.query('DELETE FROM license_assignments WHERE license_id=$1', [license.id]);
  for (const type of ['user', 'device']) await assert.rejects(pool.query('INSERT INTO license_assignments(license_id,assignee_type,assignee_id,assigned_by) VALUES($1,$2,$3,$4)', [license.id, type, beneficiary.principal.userId, manager.principal.userId]), error => error.code === '23514');
  await clock(61); await assert.rejects(pool.query('INSERT INTO license_assignments(license_id,assignee_type,assignee_id,assigned_by,expires_at) VALUES($1,$2,$3,$4,license_now()+interval \'60 seconds\')', [license.id, 'user', beneficiary.principal.userId, manager.principal.userId]), error => error.code === '23514');
});
test('an unanswered deadline removes actual effective entitlement before a sweep and cannot be retained late', async () => {
  const license = await product(); await direct(license); await configure(license); const [initial] = await queue();
  await clock(61); assert.equal((await effective(license)).length, 0); const expired = await reviews.get(initial.id, voter.user, voter.principal); assert.equal(expired.state, 'expired');
  await assert.rejects(decision(expired), error => error.status === 403);
  await allocator.expireAll(); assert.equal((await pool.query('SELECT used_seats FROM license_catalog')).rows[0].used_seats, 0);
  assert.equal((await pool.query('SELECT COUNT(*)::int AS count FROM license_assignment_sources')).rows[0].count, 0);
});
test('group denial disables its parent, preserves a direct overlap and cannot be undone by reconciliation', async () => {
  const license = await product(); const rule = await groupGrant(license); await direct(license); await configure(license);
  const row = (await queue()).find(row => row.kind === 'group'); const denied = await decision(row, 'deny'); assert.equal(denied.state, 'denied');
  assert.equal((await effective(license)).length, 1); await groups.reconcile(license.id, rule.group_id, manager.principal.userId, manager);
  assert.equal((await pool.query('SELECT enabled FROM license_group_rules')).rows[0].enabled, false); assert.equal((await effective(license)).length, 1);
});
test('group unanswered cutoffs disable reconciliation and explicit regrant receives a new reviewed incarnation', async () => {
  const license = await product(); const rule = await groupGrant(license); await configure(license); await clock(61);
  assert.equal((await effective(license)).length, 0); await groups.reconcile(license.id, rule.group_id, manager.principal.userId, manager);
  assert.equal((await pool.query('SELECT status FROM license_group_rules')).rows[0].status, 'review-expired');
  const result = await allocator.assign(license.id, { assignee_type: 'group', assignee_id: rule.group_id }, manager.principal.userId, manager);
  assert.notEqual(result.rule.grant_id, rule.grant_id); assert.equal((await effective(license)).length, 1); assert.equal((await queue()).filter(row => row.state === 'pending').length, 1);
});
test('policy retirement changes the decision tag but leaves unanswered cutoffs binding', async () => {
  const license = await product(); await direct(license); const policy = await configure(license); const [before] = await queue();
  const retired = await reviews.retire(policy.id, policyTag(policy), { reason: 'Stop future review enrollment without reviving grants', acknowledgeDeadlines: true }, configurator.user, configurator.principal, configurator.authorization);
  assert.ok(retired.retiredAt); await assert.rejects(decision(before), error => error.status === 412);
  const [current] = await queue(); assert.equal((await decision(current)).state, 'exempt');
  assert.equal((await effective(license))[0].expires_at, null);
});
test('retirement and replacement cannot rescue expired review targets or extend a still-pending earlier cutoff', async () => {
  const license = await product(); await direct(license); const policy = await configure(license); const [before] = await queue();
  await reviews.retire(policy.id, policyTag(policy), { reason: 'Replace policy without extending its accepted cutoff', acknowledgeDeadlines: true }, configurator.user, configurator.principal, configurator.authorization);
  await configure(license, { windowSeconds: 120 }); const [rebound] = await queue(); assert.equal(rebound.deadlineAt, before.deadlineAt);
  await clock(61); assert.equal((await effective(license)).length, 0); assert.equal((await queue())[0].state, 'expired');
});
test('configuration rejects unavailable, self-only, noncanonical and unsupported review scopes', async () => {
  const license = await product(); await direct(license, voter); await assert.rejects(configure(license), error => error.status === 403);
  const empty = await product(); unavailable = true; await assert.rejects(configure(empty), error => error.status === 409); unavailable = false;
  await pool.query("UPDATE license_catalog SET license_type='per_device' WHERE id=$1", [empty.id]); await assert.rejects(configure(empty), error => error.status === 409);
  const other = await product(); await pool.query("INSERT INTO license_assignment_sources(license_id,user_id,source_type,source_id,assigned_by) VALUES($1,'opaque-legacy','direct','direct','migration')", [other.id]);
  await assert.rejects(configure(other), error => error.status === 400);
});
test('future self-only grants and all-beneficiary groups cannot bypass the configured independent path', async () => {
  const license = await product(); await configure(license);
  await assert.rejects(direct(license, voter), error => error.code === '23514');
  await assert.rejects(groupGrant(license, [voter.principal.userId]), error => error.code === '23514');
  assert.equal((await effective(license)).length, 0);
});
test('current canonical group membership is checked even when its new beneficiary has not reconciled locally', async () => {
  const license = await product(); const rule = await groupGrant(license); await configure(license); const [row] = await queue();
  directoryGroups.get(rule.group_id).members.push(voter.principal.userId); directoryGroups.get(rule.group_id).revision = '2';
  await assert.rejects(decision(row), error => error.status === 403);
  directoryGroups.get(rule.group_id).members.pop(); directoryGroups.get(rule.group_id).unresolved = ['legacy']; await assert.rejects(decision(row), error => error.status === 503);
});
test('source semantic changes invalidate old decisions without extending the review deadline', async () => {
  const license = await product(); const rule = await groupGrant(license); await configure(license); const [before] = await queue();
  directoryGroups.get(rule.group_id).members.push(actor('user').principal.userId); directoryGroups.get(rule.group_id).revision = '2';
  await groups.reconcile(license.id, rule.group_id, manager.principal.userId, manager); const [current] = await queue();
  assert.equal(current.deadlineAt, before.deadlineAt); assert.notEqual(current.sourceVersion, before.sourceVersion);
  await assert.rejects(decision(before), error => error.status === 412);
});
test('post-DML loss of original authority rolls back the cycle, projection and audit', async () => {
  const license = await product(); await direct(license); await configure(license); const [before] = await queue(); const projection = await effective(license);
  validations = 0; fault = async count => { if (count === 2) throw Object.assign(new Error('Owned revoked issuer session'), { status: 401 }); };
  await assert.rejects(decision(before), error => error.status === 401); assert.deepEqual((await queue())[0], before); assert.deepEqual(await effective(license), projection);
  assert.equal((await pool.query("SELECT COUNT(*)::int AS count FROM license_review_audit WHERE action='retain'")).rows[0].count, 0);
});
test('directory membership gained during review DML cannot commit self-certification', async () => {
  const license = await product(); const rule = await groupGrant(license); await configure(license); const [before] = await queue();
  validations = 0; fault = async count => { if (count === 1) { directoryGroups.get(rule.group_id).members.push(voter.principal.userId); directoryGroups.get(rule.group_id).revision = '2'; } };
  await assert.rejects(decision(before), error => error.status === 403); assert.equal((await queue())[0].version, before.version);
});
test('review duties do not imply allocation, policy management or unassigned reading', async () => {
  const license = await product(); await direct(license); await configure(license); const [row] = await queue();
  assert.equal((await reviews.get(row.id, reader.user, reader.principal)).canDecide, false);
  for (const who of [manager, actor('access-reviewer'), actor('license-reviewer')]) await assert.rejects(reviews.get(row.id, who.user, who.principal), error => error.status === 404);
  await assert.rejects(decision(row, 'retain', reader), error => error.status === 403);
  const weak = { ...voter, user: { ...voter.user, amr: ['pwd'] } }; await assert.rejects(decision(row, 'retain', weak), error => error.status === 428);
});
