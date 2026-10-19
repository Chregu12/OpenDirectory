'use strict';

const { provenMfa } = require('../../../../../packages/mfa-authorization-contract');
const { validContext } = require('../../../../../packages/identity-authorization-contract');
const { createAccessStateClient } = require('../../../../../packages/oidc-access-state');
const { getLicensePermissions } = require('../middleware/licenseAccess');
const { LicenseError } = require('./LicenseError');
const { requirePrincipal, UUID } = require('./LicensePrincipal');
const { LicenseGrants } = require('./LicenseGrants');
const { syncRecipients, withdrawSource } = require('./LicenseSourceMutation');
const iso = value => value ? new Date(value).toISOString() : null;
const policyTag = row => `"od-license-review-policy:${row.id}:${row.version}"`;
const reviewTag = row => `"od-license-review:${row.id}:${row.version}:${row.policyVersion}:${row.sourceVersion}"`;
const fail = (status, code) => { throw new LicenseError(status, code); };
const uuid = value => { if (typeof value !== 'string' || !UUID.test(value)) fail(400, 'canonical_uuid_required'); return value; };
function fields(body, keys) {
  if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).length !== keys.length || keys.some(key => !Object.hasOwn(body, key))) fail(400, 'invalid_review_fields');
  if (typeof body.reason !== 'string' || body.reason.trim().length < 10 || body.reason.length > 500 || /[\u0000-\u001f\u007f]/.test(body.reason)) fail(400, 'review_reason_required');
}
const SELECT = `SELECT lease.*,policy.license_id,policy.version AS policy_version,policy.retired_at,policy.reviewer_user_ids,
 grants.kind,grants.recipient_id,event.version AS source_version,event.expires_at AS base_expires_at,
 license_now() AS observed_at,EXISTS(SELECT 1 FROM license_assignment_sources WHERE grant_id=grants.id AND user_id=$2) AS local_beneficiary,
 event.state='active' AND (event.expires_at IS NULL OR event.expires_at>license_now()) AND
 CASE WHEN grants.kind='group' THEN EXISTS(SELECT 1 FROM license_group_rules WHERE grant_id=grants.id AND enabled)
 ELSE grants.eligibility_revision IS NOT NULL AND EXISTS(SELECT 1 FROM license_assignment_sources source JOIN license_subjects subject ON subject.user_id=source.user_id
   WHERE source.grant_id=grants.id AND subject.directory_revision=grants.eligibility_revision AND NOT subject.disabled AND subject.directory_enabled) END AS source_current
 FROM license_review_leases lease JOIN license_review_policies policy ON policy.id=lease.policy_id
 JOIN license_catalog catalog ON catalog.id=policy.license_id AND catalog.business_tenant_id IS NULL JOIN license_grants grants ON grants.id=lease.grant_id
 JOIN LATERAL(SELECT * FROM license_grant_events WHERE grant_id=grants.id ORDER BY version DESC LIMIT 1) event ON true`;

class LicenseReviews {
  constructor(allocator, { source = allocator.users.source, revalidate } = {}) {
    this.allocator = allocator; this.database = allocator.database; this.source = source;
    this.revalidate = revalidate || createAccessStateClient(); this.grants = new LicenseGrants(allocator);
  }
  actor(user, principal, permission, write = false) {
    requirePrincipal(principal);
    if (user?.actor_type !== 'user' || user.iss !== principal.issuer || user.sub !== principal.subject
      || !validContext(user.identity_authorization) || user.identity_authorization.userId !== principal.userId) fail(403, 'canonical_human_required');
    if (permission && !getLicensePermissions(user).includes('licenses.reviews.' + permission)) fail(403, 'forbidden');
    const fresh = provenMfa(user) && user.auth_time <= Math.floor(Date.now() / 1000) + 5 && Math.floor(Date.now() / 1000) - user.auth_time <= 300;
    if (write && !fresh) fail(428, 'fresh_mfa_required');
    return { userId: principal.userId, issuer: principal.issuer, subject: principal.subject, fresh };
  }
  async context(client, body, action, user, principal, review = null) {
    const proof = { userId: principal.userId, issuer: principal.issuer, subject: principal.subject, authTime: user.auth_time, factorRevision: user.mfa_authorization.revision,
      reviewedSourceVersion: review?.sourceVersion || null, reviewedPolicyVersion: review?.policyVersion || null };
    await client.query("SELECT set_config('opendirectory.license_review_action',$1,true),set_config('opendirectory.license_review_reason',$2,true),set_config('opendirectory.license_review_proof',$3,true)", [action, body.reason.trim(), JSON.stringify(proof)]);
    await client.query("SELECT set_config('opendirectory.license_actor_user',$1,true),set_config('opendirectory.license_actor_issuer',$2,true),set_config('opendirectory.license_actor_subject',$3,true)", [principal.userId, principal.issuer, principal.subject]);
  }
  async inPool(licenseId, actor, grantId, operation) {
    await this.allocator.assertPoolAccess(licenseId, this.database, { legacyOnly: true });
    const read = client => client.query('SELECT user_id FROM license_assignment_sources WHERE license_id=$1 AND ($2::uuid IS NULL OR grant_id=$2) LIMIT 10001', [licenseId, grantId]);
    const previous = await read(this.database);
    if (previous.rows.length > 10000) fail(409, 'review_operation_requires_bounded_sources');
    const identifiers = [...new Set([actor, ...previous.rows.map(row => uuid(row.user_id))])].sort();
    for (const identifier of identifiers) await this.allocator.assertLegacySubject(identifier);
    return this.allocator.transaction(async client => {
      await this.allocator.assertPoolAccess(licenseId, client, { legacyOnly: true });
      for (const identifier of identifiers) await this.allocator.assertLegacySubject(identifier, client);
      await client.query('INSERT INTO license_subjects(user_id) SELECT identifier FROM unnest($1::text[]) identifier ORDER BY identifier COLLATE "C" ON CONFLICT DO NOTHING', [identifiers]);
      const locked = (await client.query('SELECT * FROM license_subjects WHERE user_id=ANY($1::text[]) AND business_tenant_id IS NULL ORDER BY user_id COLLATE "C" FOR UPDATE', [identifiers])).rows;
      if (locked.length !== identifiers.length) fail(404, 'legacy_license_subject_not_found');
      const actorState = locked.find(state => state.user_id === actor);
      if (!actorState || actorState.disabled || actorState.directory_enabled === false) fail(403, 'license_actor_disabled');
      const pool = await this.allocator.lockLicense(client, licenseId);
      const sources = await read(client);
      if (sources.rows.length > 10000 || sources.rows.some(row => !identifiers.includes(row.user_id))) fail(409, 'license_sources_changed');
      return operation(client, pool, sources.rows);
    });
  }
  policyView(row) {
    return { id: row.id, licenseId: row.license_id, version: String(row.version), intervalSeconds: row.interval_seconds, windowSeconds: row.window_seconds,
      reviewerUserIds: row.reviewer_user_ids, createdAt: iso(row.created_at), retiredAt: iso(row.retired_at) };
  }
  async policy(licenseId, user, principal) {
    this.actor(user, principal, 'policies.read'); uuid(licenseId);
    await this.allocator.assertPoolAccess(licenseId, this.database, { legacyOnly: true });
    const row = (await this.database.query('SELECT * FROM license_review_policies WHERE license_id=$1 ORDER BY (retired_at IS NULL) DESC,created_at DESC,id LIMIT 1', [licenseId])).rows[0];
    return { licenseId, policy: row ? this.policyView(row) : null };
  }
  async reviewers(ids, authorization, deadline = Infinity) {
    for (const identifier of ids) {
      if (Date.now() > deadline) fail(503, 'license_review_verification_timeout');
      await this.allocator.assertLegacySubject(identifier);
      if (!(await this.source.reviewer(identifier, authorization)).canReview) fail(409, 'reviewer_unavailable');
    }
  }
  async inventory(client, licenseId) {
    await this.allocator.assertPoolAccess(licenseId, client, { legacyOnly: true });
    const rows = (await client.query(`SELECT grants.* FROM license_grants grants WHERE license_id=$1 AND
      (EXISTS(SELECT 1 FROM license_group_rules WHERE grant_id=grants.id AND enabled AND (license_source_expiry(grant_id,expires_at) IS NULL OR license_source_expiry(grant_id,expires_at)>license_now()))
       OR EXISTS(SELECT 1 FROM license_assignment_sources WHERE grant_id=grants.id AND source_type='direct' AND (license_source_expiry(grant_id,expires_at) IS NULL OR license_source_expiry(grant_id,expires_at)>license_now())))
      ORDER BY grants.id LIMIT 1001`, [licenseId])).rows;
    if (rows.length > 1000) fail(409, 'review_configuration_requires_bounded_pool');
    return rows;
  }
  async independent(target, reviewerIds, context, client) {
    if (Date.now() > context.deadline) fail(503, 'license_review_verification_timeout');
    uuid(target.recipient_id);
    let beneficiaries;
    if (target.kind === 'direct') {
      const snapshot = await this.allocator.users.read(target.recipient_id, context.authorization);
      if (!snapshot.enabled || snapshot.deleted) fail(409, 'active_canonical_target_required');
      const origin = (await client.query('SELECT eligibility_revision FROM license_grants WHERE id=$1', [target.id])).rows[0];
      if (origin?.eligibility_revision == null || String(origin.eligibility_revision) !== snapshot.revision) fail(409, 'license_source_eligibility_changed');
      beneficiaries = [target.recipient_id];
    } else {
      const snapshot = await this.allocator.groups.snapshot(target.recipient_id, context);
      if (snapshot.deleted) fail(409, 'active_canonical_group_required');
      const local = await client.query('SELECT user_id FROM license_assignment_sources WHERE grant_id=$1', [target.id]);
      beneficiaries = [...snapshot.memberIds, ...snapshot.inactiveMemberIds, ...local.rows.map(row => uuid(row.user_id))];
    }
    if (!reviewerIds.some(identifier => !beneficiaries.includes(identifier))) fail(403, 'independent_license_reviewer_required');
    if (Date.now() > context.deadline) fail(503, 'license_review_verification_timeout');
  }
  async create(body, user, principal, authorization) {
    const actor = this.actor(user, principal, 'policies.manage', true);
    fields(body, ['licenseId', 'intervalSeconds', 'windowSeconds', 'reviewerUserIds', 'reason', 'acknowledgeDeadlines']); uuid(body.licenseId);
    if (!Number.isInteger(body.intervalSeconds) || body.intervalSeconds < 3600 || body.intervalSeconds > 31536000
      || !Number.isInteger(body.windowSeconds) || body.windowSeconds < 60 || body.windowSeconds > 604800 || body.windowSeconds >= body.intervalSeconds
      || body.acknowledgeDeadlines !== true || !Array.isArray(body.reviewerUserIds) || !body.reviewerUserIds.length || body.reviewerUserIds.length > 20
      || body.reviewerUserIds.some((identifier, index) => uuid(identifier) !== identifier || index > 0 && body.reviewerUserIds[index - 1] >= identifier)) fail(400, 'invalid_review_policy');
    await this.allocator.assertPoolAccess(body.licenseId, this.database, { legacyOnly: true });
    await this.reviewers(body.reviewerUserIds, authorization);
    return this.inPool(body.licenseId, actor.userId, null, async (client, pool, sources) => {
      if (!['per_user', 'subscription'].includes(pool.license_type)) fail(409, 'human_license_pool_required');
      const targets = await this.inventory(client, pool.id); const context = { principal, authorization, deadline: Date.now() + 30000 };
      for (const target of targets) await this.independent(target, body.reviewerUserIds, context, client);
      await this.revalidate(authorization, user); this.actor(user, principal, 'policies.manage', true);
      await this.context(client, body, 'configure', user, principal);
      const row = (await client.query('INSERT INTO license_review_policies(license_id,interval_seconds,window_seconds,reviewer_user_ids) VALUES($1,$2,$3,$4) RETURNING *', [pool.id, body.intervalSeconds, body.windowSeconds, body.reviewerUserIds])).rows[0];
      await syncRecipients(this.allocator, client, pool.id, sources, actor.userId, context.deadline);
      await this.reviewers(body.reviewerUserIds, authorization, context.deadline);
      for (const target of targets) await this.independent(target, body.reviewerUserIds, context, client);
      await this.revalidate(authorization, user); this.actor(user, principal, 'policies.manage', true);
      return this.policyView(row);
    });
  }
  async retire(id, expected, body, user, principal, authorization) {
    const actor = this.actor(user, principal, 'policies.manage', true); uuid(id); fields(body, ['reason', 'acknowledgeDeadlines']);
    if (body.acknowledgeDeadlines !== true) fail(400, 'deadline_acknowledgement_required'); if (!expected) fail(428, 'version_required');
    const previous = (await this.database.query('SELECT policy.license_id FROM license_review_policies policy JOIN license_catalog catalog ON catalog.id=policy.license_id AND catalog.business_tenant_id IS NULL WHERE policy.id=$1', [id])).rows[0]; if (!previous) fail(404, 'review_policy_not_found');
    return this.inPool(previous.license_id, actor.userId, null, async client => {
      const row = (await client.query('SELECT * FROM license_review_policies WHERE id=$1 FOR UPDATE', [id])).rows[0];
      if (expected !== policyTag(row)) fail(412, 'review_policy_changed'); if (row.retired_at) fail(409, 'review_policy_retired');
      await this.revalidate(authorization, user); await this.context(client, body, 'retire', user, principal);
      const result = (await client.query('UPDATE license_review_policies SET retired_at=license_now(),version=version+1 WHERE id=$1 RETURNING *', [id])).rows[0];
      await this.revalidate(authorization, user); this.actor(user, principal, 'policies.manage', true); return this.policyView(result);
    });
  }
  view(row, user, principal) {
    const actor = this.actor(user, principal); const permissions = getLicensePermissions(user);
    if (!row || !permissions.includes('licenses.reviews.all.read') && !(permissions.includes('licenses.reviews.assigned.read') && row.reviewer_user_ids.includes(actor.userId))) fail(404, 'license_review_not_found');
    const state = row.state === 'denied' ? 'denied' : !row.source_current ? 'obsolete' : row.deadline_at && row.deadline_at <= row.observed_at ? 'expired'
      : row.state === 'exempt' ? 'exempt' : row.due_at > row.observed_at ? 'scheduled' : 'pending';
    const self = row.kind === 'direct' && row.recipient_id === actor.userId || row.local_beneficiary;
    const allowed = permissions.includes('licenses.reviews.decide') && row.reviewer_user_ids.includes(actor.userId) && !self && state === 'pending';
    return { id: row.id, policyId: row.policy_id, licenseId: row.license_id, grantId: row.grant_id, kind: row.kind, recipientId: row.recipient_id,
      version: String(row.version), policyVersion: String(row.policy_version), sourceVersion: String(row.source_version), cycle: String(row.cycle),
      dueAt: iso(row.due_at), deadlineAt: iso(row.deadline_at), baseExpiresAt: iso(row.base_expires_at), state, policyRetired: !!row.retired_at,
      canDecide: !!allowed && actor.fresh, requiresFreshMfa: !!allowed && !actor.fresh, selfReview: !!self };
  }
  async get(id, user, principal, client = this.database) {
    uuid(id); this.actor(user, principal);
    const permissions = getLicensePermissions(user);
    if (!permissions.some(permission => ['licenses.reviews.all.read', 'licenses.reviews.assigned.read'].includes(permission))) fail(404, 'license_review_not_found');
    return this.view((await client.query(SELECT + ' WHERE lease.id=$1', [id, principal.userId])).rows[0], user, principal);
  }
  async self(user, principal) {
    const actor = this.actor(user, principal, 'assigned.read');
    const rows = (await this.database.query(`SELECT * FROM (${SELECT} WHERE policy.reviewer_user_ids @> ARRAY[$1::uuid]) current
      ORDER BY (state='pending' AND due_at<=observed_at AND deadline_at>observed_at AND source_current AND NOT local_beneficiary) IS TRUE DESC,deadline_at,id LIMIT 101`, [actor.userId, actor.userId])).rows;
    return { userId: actor.userId, reviews: rows.slice(0, 100).map(row => this.view(row, user, principal)), truncated: rows.length > 100 };
  }
  async decide(id, expected, body, user, principal, authorization) {
    const actor = this.actor(user, principal, 'decide', true); fields(body, ['decision', 'reason', 'acknowledgeScope']); uuid(id);
    if (!['retain', 'deny'].includes(body.decision) || body.acknowledgeScope !== true) fail(400, 'review_decision_required'); if (!expected) fail(428, 'version_required');
    const peek = await this.get(id, user, principal);
    return this.inPool(peek.licenseId, actor.userId, peek.grantId, async (client, pool, sources) => {
      const current = await this.get(id, user, principal, client);
      if (expected !== reviewTag(current)) fail(412, 'license_review_changed'); if (!current.canDecide) fail(403, 'license_review_not_decidable');
      const target = { id: current.grantId, kind: current.kind, recipient_id: current.recipientId };
      const context = { principal, authorization, deadline: Date.now() + 30000 }; await this.independent(target, [actor.userId], context, client);
      await this.revalidate(authorization, user); this.actor(user, principal, 'decide', true);
      await this.context(client, body, body.decision, user, principal, current);
      if (body.decision === 'deny') await withdrawSource(this.allocator, client, { id: current.grantId, licenseId: current.licenseId, kind: current.kind, recipientId: current.recipientId }, actor.userId, context.deadline);
      await client.query('UPDATE license_review_leases SET version=version+1 WHERE id=$1', [id]);
      if (body.decision === 'retain') await syncRecipients(this.allocator, client, pool.id, sources, actor.userId, context.deadline);
      await this.independent(target, [actor.userId], context, client);
      const result = await this.get(id, user, principal, client);
      await this.revalidate(authorization, user); this.actor(user, principal, 'decide', true);
      return result;
    });
  }
}

module.exports = { LicenseReviews, policyTag, reviewTag };
