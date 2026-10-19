'use strict';

const { identifier, normalizeReview } = require('../../../../packages/company-registration-contract');
const { validContext } = require('../../../../packages/identity-authorization-contract');
const { acceptsRoleAuthentication } = require('../../../../packages/role-authentication-contract');
const { authorityTenant } = require('./AuthorityTenant');
const { readRoleState } = require('./RoleState');
const { AuthorityCommand } = require('./AuthorityCommand');
const PERMISSION = 'company.registrations.review';
const ASSURANCE = { required: true, maxAgeSeconds: 300 };
function fail(status, code) { throw Object.assign(new Error(code), { status, code }); }
function proof(user) {
  if (user?.actor_type !== 'user' || !validContext(user.identity_authorization) || typeof user.iss !== 'string' || !user.iss || typeof user.sub !== 'string' || !user.sub) fail(403, 'canonical_human_required');
  return { ...user.identity_authorization, issuer: user.iss, subject: user.sub };
}
function reviewError(error) {
  if (['40001', '23505'].includes(error.code)) fail(412, 'company_review_changed');
  if (error.code === '23503') fail(404, 'registration_not_found');
  if (error.code === '23514') fail(400, 'invalid_company_review');
  if (error.code === '42501') fail(503, 'company_review_unavailable');
  throw error;
}
class CompanyRegistrationReviews {
  constructor(database, options = {}) { this.database = database; this.commands = new AuthorityCommand(database, options); }
  async operator(client, user) {
    const actor = proof(user); await client.query("SET LOCAL timezone='UTC'");
    const home = await authorityTenant(client, actor); const state = await readRoleState(client, actor.userId);
    if (state.rolesRevision !== actor.rolesRevision) fail(401, 'company_reviewer_changed');
    const source = (await client.query(`SELECT operator.*,identity_company_review_operator_valid(operator) AS valid FROM identity_company_review_operators operator
      WHERE issuer=$1 AND user_id=$2`, [actor.issuer, actor.userId])).rows[0];
    if (!source || !source.enabled) fail(403, 'explicit_company_reviewer_required');
    if (!source.valid || source.tenant_id !== home) fail(503, 'company_review_unavailable');
    if (!acceptsRoleAuthentication(state.authentication, user) || !acceptsRoleAuthentication(ASSURANCE, user)) fail(428, 'fresh_mfa_required');
    await client.query('SELECT identity_company_review_receiving()'); return actor;
  }
  async permissions(user) {
    if (user?.actor_type !== 'user' || !validContext(user.identity_authorization)) return [];
    return this.database.transaction(async client => {
      const actor = proof(user); await authorityTenant(client, actor);
      const row = (await client.query(`SELECT operator.enabled,identity_company_review_operator_valid(operator) AS valid FROM identity_company_review_operators operator
        WHERE issuer=$1 AND user_id=$2`, [actor.issuer, actor.userId])).rows[0];
      if (row?.enabled && !row.valid) fail(503, 'company_review_unavailable'); return row?.enabled ? [PERMISSION] : [];
    }, { readOnly: true }).catch(reviewError);
  }
  async view(client, identifierValue, actor) {
    const row = (await client.query(`SELECT registration.*,identity_company_registration_retained_valid(registration.id) AS valid,review.id AS review_id,review.decision,review.created_at AS reviewed_at,activation.id AS activation_id,identity_company_owner_active(activation) AS owner_active,
      identity_company_review_valid(registration.id) AS review_valid,event.reason,event.actor AS reviewer
      FROM identity_company_registrations registration LEFT JOIN identity_company_registration_reviews review ON review.registration_id=registration.id
      LEFT JOIN identity_company_activations activation ON activation.registration_id=registration.id
      LEFT JOIN identity_company_review_events event ON event.id=review.id WHERE registration.id=$1`, [identifierValue])).rows[0];
    if (!row) fail(404, 'registration_not_found');
    if (row.activation_id) await client.query('SELECT identity_company_activation_receiving()');
    if (!row.valid || row.review_id && !row.review_valid) fail(503, 'company_review_unavailable');
    return { schemaVersion: 1, actorUserId: actor.userId, registrationId: row.id, tenantId: row.tenant_id, administratorId: row.user_id,
      principal: { username: row.username, email: row.email, displayName: row.display_name }, profile: row.profile, createdAt: row.created_at.toISOString(),
      status: row.activation_id ? row.owner_active ? 'active' : 'suspended' : row.decision === 'approved' ? 'pending-activation' : row.decision === 'rejected' ? 'rejected' : 'pending-verification',
      etag: `"company-review-${row.id}-${row.payload_sha256}-${row.review_id || 'pending'}${row.activation_id ? row.owner_active ? '-active' : '-suspended' : ''}"`, activationSupported: false,
      canReview: !row.review_id && row.user_id !== actor.userId && !(row.issuer === actor.issuer && row.subject === actor.subject),
      review: row.review_id ? { id: row.review_id, decision: row.decision, reviewedAt: row.reviewed_at.toISOString(), reason: row.reason, reviewerUserId: row.reviewer.userId } : null };
  }
  async get(id, user) {
    if (!identifier(id)) fail(400, 'invalid_registration_id'); user = structuredClone(user);
    return this.database.transaction(async client => this.view(client, id, await this.operator(client, user)), { readOnly: true }).catch(reviewError);
  }
  async list(query, user) {
    const allowed = ['page', 'limit', 'status'];
    if (!query || Object.keys(query).some(key => !allowed.includes(key)) || ['page', 'limit'].some(key => query[key] !== undefined && (typeof query[key] !== 'string' || !/^[1-9][0-9]{0,5}$/.test(query[key])))
      || query.status !== undefined && !['pending-verification', 'pending-activation', 'rejected', 'active', 'suspended', 'all'].includes(query.status)) fail(400, 'invalid_company_review_filter');
    const page = Number(query.page || 1); const limit = Number(query.limit || 20); if (page > 10000 || limit > 50) fail(400, 'invalid_company_review_filter');
    const status = query.status || 'pending-verification'; user = structuredClone(user);
    return this.database.transaction(async client => {
      const actor = await this.operator(client, user);
      const filter = `($1='all' OR $1=CASE WHEN activation.id IS NOT NULL THEN CASE WHEN identity_company_owner_active(activation) THEN 'active' ELSE 'suspended' END WHEN review.decision='approved' THEN 'pending-activation' WHEN review.decision='rejected' THEN 'rejected' ELSE 'pending-verification' END)`;
      const joins = 'LEFT JOIN identity_company_registration_reviews review ON review.registration_id=registration.id LEFT JOIN identity_company_activations activation ON activation.registration_id=registration.id';
      const total = (await client.query(`SELECT count(*)::int AS count FROM identity_company_registrations registration ${joins} WHERE ${filter}`, [status])).rows[0].count;
      const rows = (await client.query(`SELECT registration.id FROM identity_company_registrations registration ${joins}
        WHERE ${filter} ORDER BY registration.created_at DESC,registration.id DESC LIMIT $2 OFFSET $3`, [status, limit, (page - 1) * limit])).rows;
      const registrations = []; for (const row of rows) registrations.push(await this.view(client, row.id, actor));
      return { schemaVersion: 1, actorUserId: actor.userId, page, limit, status, total, registrations };
    }, { readOnly: true }).catch(reviewError);
  }
  async decide(id, body, etag, user, authorization) {
    if (!identifier(id)) fail(400, 'invalid_registration_id'); const change = normalizeReview(body); user = structuredClone(user); const actor = proof(user);
    if (typeof etag !== 'string' || !etag) fail(428, 'company_review_version_required');
    if (!acceptsRoleAuthentication(ASSURANCE, user)) fail(428, 'fresh_mfa_required');
    return this.commands.run(user, authorization, async client => {
      await this.operator(client, user); const before = await this.view(client, id, actor);
      if (etag !== before.etag) fail(412, 'company_review_changed'); if (!before.canReview) fail(409, 'company_already_reviewed');
      const result = await client.query('SELECT identity_company_review_decide($1::jsonb,$2,$3,$4,$5,$6,$7::bigint) AS id',
        [JSON.stringify(actor), user.jti, id, etag, change.decision, change.reason, String(Math.min(user.exp, user.auth_time + 300))]);
      const after = await this.view(client, id, actor);
      if (!identifier(result.rows[0]?.id) || after.review?.id !== result.rows[0].id || after.review.decision !== change.decision) fail(503, 'company_review_unavailable'); return after;
    }, { actor: JSON.stringify(actor) }, ASSURANCE).catch(reviewError);
  }
}
module.exports = { CompanyRegistrationReviews, PERMISSION };
