'use strict';

const { ROLES, PROTECTED } = require('../../../../packages/directory-role-contract');
const { validContext } = require('../../../../packages/identity-authorization-contract');
const { provenMfa } = require('../../../../packages/mfa-authorization-contract');
const { readRoleState } = require('./AuthorizationState');
const { getIdentityPermissions } = require('./middleware/identityAccess');
const { acceptsRoleAuthentication } = require('../../../../packages/role-authentication-contract');
const { authorityTenant, lockAuthorityUsers, requireAuthorityReceiver } = require('./AuthorityTenant');
const { AuthorityCommand } = require('./AuthorityCommand');
function fail(status, code) { throw Object.assign(new Error(code), { status, code }); }
function uuid(value) {
  if (typeof value !== 'string' || value.length !== 36 || !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(value)) fail(400, 'canonical_uuid_required');
  return value.toLowerCase();
}
function fields(body, allowed) {
  if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).some(key => !allowed.includes(key))) fail(400, 'invalid_fields');
}
function reason(value) { if (typeof value !== 'string' || value.trim().length < 10 || value.length > 500 || /[\u0000-\u001f\u007f]/.test(value)) fail(400, 'reason_required'); return value.trim(); }
function duration(value, maximum = 28800) { if (!Number.isInteger(value) || value < 60 || value > maximum) fail(400, 'invalid_duration'); return value; }
function authority(user) {
  if (user?.actor_type !== 'user' || !validContext(user.identity_authorization) || typeof user.iss !== 'string' || !user.iss
    || typeof user.sub !== 'string' || !user.sub.trim()) fail(403, 'canonical_human_required');
  return { ...user.identity_authorization, issuer: user.iss, subject: user.sub };
}
const REQUEST_SELECT = `SELECT request.*,eligibility.role,eligibility.revoked_at AS eligibility_revoked_at,eligibility.expires_at AS eligibility_expires_at,
  assignment.id AS assignment_id,assignment.expires_at AS assignment_expires_at,assignment.revoked_at AS assignment_revoked_at,policy.version AS activation_version,
  policy.activation_required,policy.reviewer_user_ids,identity_role_review_eligible(eligibility.id) AS eligibility_review_eligible,
  NOT EXISTS(SELECT 1 FROM identity_role_review_leases review WHERE review.target_kind='assignment' AND review.target_id=assignment.id
    AND (review.state='denied' OR review.deadline_at<=identity_role_review_now())) AS assignment_review_eligible,
  users.enabled AS user_enabled,users.authorization_revision AS current_revision,binding.authorization_revision AS current_link_revision,clock_timestamp() AS observed_at
  FROM identity_pim_requests request JOIN identity_pim_eligibilities eligibility ON eligibility.id=request.eligibility_id AND eligibility.user_id=request.user_id
  JOIN identity_role_activation_policies policy ON policy.role=eligibility.role
  LEFT JOIN identity_role_assignments assignment ON assignment.activation_request_id=request.id AND assignment.user_id=request.user_id
  LEFT JOIN users ON users.id=request.user_id LEFT JOIN identity_subject_links binding ON binding.user_id=request.user_id
    AND binding.issuer=request.request_authority->>'issuer' AND binding.subject=request.request_authority->>'subject'`;
const iso = value => value ? new Date(value).toISOString() : null;
function eligibilityView(row) {
  return { id: row.id, userId: row.user_id, role: row.role, reason: row.reason, maxDurationSeconds: row.max_duration_seconds,
    createdAt: iso(row.created_at), expiresAt: iso(row.expires_at), revokedAt: iso(row.revoked_at),
    status: row.revoked_at ? 'revoked' : row.review_eligible===false || new Date(row.expires_at) <= new Date(row.observed_at) ? 'expired' : 'eligible' };
}
function requestView(row, rolesRevision) {
  const observed = new Date(row.observed_at).getTime(); let status = row.state;
  const approvalDeadline = row.decided_at ? Math.min(new Date(row.decided_at).getTime()+300000,
    Number.isInteger(row.decision_authority?.reviewerAuthentication?.authTime) ? row.decision_authority.reviewerAuthentication.authTime*1000+300000 : Infinity) : null;
  if (status === 'active') status = row.assignment_revoked_at ? 'revoked' : !row.assignment_id ? 'stale' : new Date(row.assignment_expires_at).getTime() <= observed ? 'expired' : 'active';
  if (['pending','approved','active'].includes(status) && (row.eligibility_review_eligible===false || status==='active' && row.assignment_review_eligible===false)) status='expired';
  if (['pending','approved','active'].includes(status) && String(row.policy_version) !== String(row.activation_version)) status = 'stale';
  if (['pending', 'approved'].includes(status)) {
    if (row.eligibility_revoked_at) status = 'cancelled';
    else if (new Date(row.deadline_at).getTime() <= observed || new Date(row.eligibility_expires_at).getTime() <= observed
      || (status === 'approved' && approvalDeadline <= observed)) status = 'expired';
    else if (!row.user_enabled || String(row.current_revision) !== row.request_authority.revision || String(row.current_link_revision) !== row.request_authority.linkRevision
      || (rolesRevision !== undefined && rolesRevision !== row.request_authority.rolesRevision)) status = 'stale';
  }
  return { id: row.id, eligibilityId: row.eligibility_id, userId: row.user_id, role: row.role, reason: row.reason,
    durationSeconds: row.duration_seconds, createdAt: iso(row.created_at), deadlineAt: iso(row.deadline_at),
    status, decidedAt: iso(row.decided_at), decidedBy: row.decision_authority?.userId || null,
    approvalExpiresAt: approvalDeadline && row.state !== 'denied' ? new Date(approvalDeadline).toISOString() : null,
    assignmentId: row.assignment_id || null, expiresAt: iso(row.assignment_expires_at) };
}

class PrivilegedActivation {
  constructor(database, options) { this.database = database; this.commands = new AuthorityCommand(database, options); }
  async lockUsers(client, identifiers, tenant) {
    return lockAuthorityUsers(client, identifiers, tenant);
  }
  async verify(client, proof, locked, permission) {
    const user = locked.find(row => row.id === proof.userId);
    if (!user?.enabled || String(user.authorization_revision) !== proof.revision) fail(409, 'authorization_changed');
    const link = await client.query('SELECT authorization_revision FROM identity_subject_links WHERE issuer=$1 AND subject=$2 AND user_id=$3 FOR SHARE', [proof.issuer, proof.subject, proof.userId]);
    const roles = await readRoleState(client, proof.userId);
    if (String(link.rows[0]?.authorization_revision) !== proof.linkRevision || roles.rolesRevision !== proof.rolesRevision) fail(409, 'authorization_changed');
    if (permission && !getIdentityPermissions({ roles: roles.roles }).includes(permission)) fail(403, 'forbidden');
    return roles.roles;
  }
  protectedRole(role, roles) { if (PROTECTED.includes(role) && !roles.includes('admin')) fail(403, 'protected_role'); }
  reviewRole(current, roles, proof, user) {
    if (!PROTECTED.includes(current.role)) return;
    if (!roles.includes('admin') && !(current.activation_required && current.reviewer_user_ids.includes(proof.userId) && roles.includes('pim-approver'))) fail(403,'protected_role');
    if (user && !acceptsRoleAuthentication({ required:true,maxAgeSeconds:300 },user)) fail(428,'fresh_mfa_required');
    if(!user && (!Number.isInteger(proof.reviewerAuthentication?.authTime) || proof.reviewerAuthentication.authTime>Math.floor(Date.now()/1000)+5
      || Math.floor(Date.now()/1000)-proof.reviewerAuthentication.authTime>300)) fail(428,'fresh_review_required');
  }
  async self(user) {
    const own = authority(user);
    return this.database.transaction(async client => {
      await authorityTenant(client, own);
      const eligibilities = await client.query('SELECT *,identity_role_review_eligible(id) AS review_eligible,clock_timestamp() AS observed_at FROM identity_pim_eligibilities WHERE user_id=$1 ORDER BY (revoked_at IS NULL AND expires_at>clock_timestamp()) DESC,created_at DESC,id LIMIT 101', [own.userId]);
      const requests = await client.query(REQUEST_SELECT + ` WHERE request.user_id=$1 ORDER BY
        ((request.policy_version=policy.version AND request.state IN ('pending','approved') AND request.deadline_at>clock_timestamp() AND (request.decided_at IS NULL OR request.decided_at+interval '5 minutes'>clock_timestamp()))
        OR (request.policy_version=policy.version AND request.state='active' AND assignment.revoked_at IS NULL AND assignment.expires_at>clock_timestamp())) DESC,request.created_at DESC,request.id LIMIT 101`, [own.userId]);
      const { rolesRevision } = await readRoleState(client, own.userId);
      return { userId: own.userId, eligibilities: eligibilities.rows.slice(0, 100).map(eligibilityView), requests: requests.rows.slice(0, 100).map(row => requestView(row, rolesRevision)),
        truncated: eligibilities.rows.length > 100 || requests.rows.length > 100 };
    }, { readOnly: true });
  }
  async eligibilities(userId, user) {
    userId = uuid(userId); const proof = authority(user);
    return this.database.transaction(async client => {
      const tenant = await authorityTenant(client, proof);
      if (!(await client.query("SELECT id FROM users WHERE id=$1 AND identity_tenant_id('user',id)=$2", [userId, tenant])).rows.length) fail(404, 'eligibility_not_found');
      const result = await client.query('SELECT *,identity_role_review_eligible(id) AS review_eligible,clock_timestamp() AS observed_at FROM identity_pim_eligibilities WHERE user_id=$1 ORDER BY (revoked_at IS NULL AND expires_at>clock_timestamp()) DESC,created_at DESC,id LIMIT 101', [userId]);
      return { userId, eligibilities: result.rows.slice(0, 100).map(eligibilityView), truncated: result.rows.length > 100 };
    }, { readOnly: true });
  }
  async queue(user) {
    const proof = authority(user);
    return this.database.transaction(async client => {
      const tenant = await authorityTenant(client, proof);
      const result = await client.query(REQUEST_SELECT + " WHERE identity_tenant_id('user',request.user_id)=$1 ORDER BY (request.policy_version=policy.version AND request.state='pending' AND request.deadline_at>clock_timestamp()) DESC,request.created_at DESC,request.id LIMIT 101", [tenant]);
      return { requests: result.rows.slice(0, 100).map(row => requestView(row)), truncated: result.rows.length > 100 };
    }, { readOnly: true });
  }
  async grantEligibility(body, user, authorization) {
    fields(body, ['userId', 'role', 'maxDurationSeconds', 'validForSeconds', 'reason']); const target = uuid(body.userId); const proof = authority(user);
    if (proof.userId === target) fail(403, 'self_eligibility_forbidden');
    if (!ROLES.includes(body.role) || body.role === 'user') fail(400, 'invalid_role');
    duration(body.maxDurationSeconds); duration(body.validForSeconds, 2592000); const explanation = reason(body.reason);
    return this.commands.run(user, authorization, async client => {
      await requireAuthorityReceiver(client); const tenant = await authorityTenant(client, proof, { write: true });
      const locked = await this.lockUsers(client, [proof.userId, target], tenant); const roles = await this.verify(client, proof, locked, 'pim.eligibilities.manage');
      this.protectedRole(body.role, roles); if (!locked.find(row => row.id === target)?.enabled) fail(409, 'recipient_not_enabled');
      const count = (await client.query('SELECT COUNT(*)::int AS count FROM identity_pim_eligibilities WHERE user_id=$1 AND revoked_at IS NULL AND expires_at>clock_timestamp() AND identity_role_review_eligible(id)', [target])).rows[0].count;
      if (count >= 100) fail(409, 'eligibility_limit');
      const result = await client.query(`INSERT INTO identity_pim_eligibilities(user_id,role,reason,max_duration_seconds,expires_at)
        VALUES($1,$2,$3,$4,clock_timestamp()+$5*interval '1 second') RETURNING *,clock_timestamp() AS observed_at`, [target, body.role, explanation, body.maxDurationSeconds, body.validForSeconds]);
      return eligibilityView(result.rows[0]);
    }, { actor: JSON.stringify(proof) });
  }
  async revokeEligibility(id, user, authorization) {
    id = uuid(id); const proof = authority(user);
    return this.commands.run(user, authorization, async client => {
      await requireAuthorityReceiver(client); const tenant = await authorityTenant(client, proof, { write: true });
      const peek = (await client.query("SELECT user_id FROM identity_pim_eligibilities WHERE id=$1 AND identity_tenant_id('user',user_id)=$2", [id, tenant])).rows[0]; if (!peek) fail(404, 'eligibility_not_found');
      if (peek.user_id === proof.userId) fail(403, 'self_eligibility_forbidden');
      const locked = await this.lockUsers(client, [proof.userId, peek.user_id], tenant); const roles = await this.verify(client, proof, locked, 'pim.eligibilities.manage');
      const current = (await client.query('SELECT * FROM identity_pim_eligibilities WHERE id=$1 FOR UPDATE', [id])).rows[0]; this.protectedRole(current.role, roles);
      if (!current.revoked_at) await client.query('UPDATE identity_pim_eligibilities SET revoked_at=clock_timestamp() WHERE id=$1', [id]);
      return { id, revoked: true };
    }, { actor: JSON.stringify(proof) });
  }
  async request(body, user, authorization) {
    fields(body, ['id', 'eligibilityId', 'durationSeconds', 'reason']);
    body = { ...body, id: uuid(body.id), eligibilityId: uuid(body.eligibilityId) }; duration(body.durationSeconds); const explanation = reason(body.reason); const proof = authority(user);
    return this.commands.run(user, authorization, async client => {
      await requireAuthorityReceiver(client); const tenant = await authorityTenant(client, proof, { write: true });
      const locked = await this.lockUsers(client, [proof.userId], tenant); await this.verify(client, proof, locked);
      const eligibility = (await client.query("SELECT *,identity_role_review_eligible(id) AS review_eligible,clock_timestamp() AS observed_at FROM identity_pim_eligibilities WHERE id=$1 AND user_id=$2 AND identity_tenant_id('user',user_id)=$3 FOR UPDATE", [body.eligibilityId, proof.userId, tenant])).rows[0];
      if (!eligibility || eligibility.user_id !== proof.userId) fail(404, 'eligibility_not_found');
      const existing = (await client.query(REQUEST_SELECT + " WHERE request.id=$1 AND identity_tenant_id('user',request.user_id)=$2", [body.id, tenant])).rows[0];
      if (existing) {
        if (existing.user_id !== proof.userId || existing.eligibility_id !== body.eligibilityId || existing.duration_seconds !== body.durationSeconds || existing.reason !== explanation) fail(409, 'request_id_conflict');
        return requestView(existing, proof.rolesRevision);
      }
      if (eligibilityView(eligibility).status !== 'eligible' || body.durationSeconds > eligibility.max_duration_seconds) fail(409, 'eligibility_unavailable');
      const open = await client.query(`SELECT id FROM identity_pim_requests WHERE eligibility_id=$1
        AND policy_version=(SELECT version FROM identity_role_activation_policies WHERE role=$2) AND
        ((state IN ('pending','approved') AND deadline_at>clock_timestamp() AND (decided_at IS NULL OR decided_at+interval '5 minutes'>clock_timestamp())
          AND (decision_authority->'reviewerAuthentication' IS NULL OR to_timestamp((decision_authority#>>'{reviewerAuthentication,authTime}')::double precision)+interval '5 minutes'>clock_timestamp()))
        OR (state='active' AND EXISTS (SELECT 1 FROM identity_role_assignments WHERE activation_request_id=identity_pim_requests.id AND revoked_at IS NULL AND expires_at>clock_timestamp()))) LIMIT 1`, [body.eligibilityId,eligibility.role]);
      if (open.rows.length) fail(409, 'request_already_open');
      await client.query(`INSERT INTO identity_pim_requests(id,eligibility_id,user_id,reason,duration_seconds,request_authority,deadline_at)
        VALUES($1,$2,$3,$4,$5,$6,LEAST(clock_timestamp()+interval '24 hours',$7))`, [body.id, body.eligibilityId, proof.userId, explanation, body.durationSeconds, JSON.stringify(proof), eligibility.expires_at]);
      return requestView((await client.query(REQUEST_SELECT + ' WHERE request.id=$1', [body.id])).rows[0]);
    }, { actor: JSON.stringify(proof) });
  }
  async change(id, action, user, authorization) {
    id = uuid(id); if (!['approve', 'deny', 'activate', 'cancel', 'revoke'].includes(action)) fail(400, 'invalid_action'); const proof = authority(user);
    return this.commands.run(user, authorization, async client => {
      await requireAuthorityReceiver(client); const tenant = await authorityTenant(client, proof, { write: true });
      const peek = (await client.query(`SELECT request.user_id,request.eligibility_id,request.decision_authority FROM identity_pim_requests request
        JOIN identity_pim_eligibilities eligibility ON eligibility.id=request.eligibility_id AND eligibility.user_id=request.user_id
        WHERE request.id=$1 AND identity_tenant_id('user',request.user_id)=$2`, [id, tenant])).rows[0]; if (!peek) fail(404, 'request_not_found');
      const owner = peek.user_id === proof.userId;
      if (['activate', 'cancel'].includes(action) && !owner) fail(404, 'request_not_found');
      if (['approve', 'deny', 'revoke'].includes(action) && owner) fail(403, 'independent_reviewer_required');
      const locked = await this.lockUsers(client, [proof.userId, peek.user_id, ...(action === 'activate' ? [peek.decision_authority?.userId] : [])], tenant);
      const roles = await this.verify(client, proof, locked, ['approve', 'deny'].includes(action) ? 'pim.requests.review' : action === 'revoke' ? 'pim.activations.revoke' : undefined);
      await client.query('SELECT id FROM identity_pim_eligibilities WHERE id=$1 FOR UPDATE', [peek.eligibility_id]);
      await client.query('SELECT id FROM identity_pim_requests WHERE id=$1 FOR UPDATE', [id]);
      const current = (await client.query(REQUEST_SELECT + ' WHERE request.id=$1', [id])).rows[0];
      const requesterRoles = await readRoleState(client, peek.user_id); const view = requestView(current, requesterRoles.rolesRevision);
      if (['approve', 'deny', 'revoke'].includes(action)) this.reviewRole(current,roles,proof,user);
      if (['approve', 'deny'].includes(action)) {
        if (view.status !== 'pending') fail(409, 'request_not_pending');
        const decision = PROTECTED.includes(current.role) ? { ...proof,reviewerAuthentication:{ authTime:user.auth_time,factorRevision:user.mfa_authorization.revision } } : proof;
        await client.query('UPDATE identity_pim_requests SET state=$2,decision_authority=$3 WHERE id=$1', [id, action === 'approve' ? 'approved' : 'denied', JSON.stringify(decision)]);
      } else if (action === 'activate') {
        if (view.status === 'active') return view;
        if (view.status !== 'approved') fail(409, 'request_not_approved');
        const now = Number((await client.query('SELECT EXTRACT(EPOCH FROM clock_timestamp()) AS now')).rows[0].now);
        if (!Number.isInteger(user.auth_time) || user.auth_time > now + 5 || now - user.auth_time > 300) fail(428, 'fresh_login_required');
        if (!provenMfa(user)) fail(428, 'verified_mfa_required');
        if (current.request_authority.issuer !== proof.issuer || current.request_authority.subject !== proof.subject
          || current.request_authority.linkRevision !== proof.linkRevision || current.request_authority.revision !== proof.revision
          || current.request_authority.rolesRevision !== proof.rolesRevision) fail(409, 'request_authorization_changed');
        const reviewerRoles = await this.verify(client, current.decision_authority, locked, 'pim.requests.review'); this.reviewRole(current,reviewerRoles,current.decision_authority);
        const count = (await client.query(`SELECT COUNT(*)::int AS count FROM identity_role_assignments assignment
          JOIN identity_role_activation_policies policy ON policy.role=assignment.role AND policy.version=assignment.policy_version
          WHERE user_id=$1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>clock_timestamp())
          AND NOT EXISTS(SELECT 1 FROM identity_role_review_leases review WHERE review.target_kind='assignment' AND review.target_id=assignment.id AND (review.state='denied' OR review.deadline_at<=identity_role_review_now()))
          AND (activation_request_id IS NULL OR identity_role_review_eligible((SELECT eligibility_id FROM identity_pim_requests WHERE id=activation_request_id)))`, [proof.userId])).rows[0].count;
        if (count >= 100 || new Date(current.eligibility_expires_at).getTime() / 1000 - now < 60) fail(409, 'activation_unavailable');
        await client.query(`INSERT INTO identity_role_assignments(user_id,role,reason,expires_at,activation_request_id)
          VALUES($1,$2,$3,LEAST(clock_timestamp()+$4*interval '1 second',$5),$6)`, [proof.userId, current.role, current.reason, current.duration_seconds, current.eligibility_expires_at, id]);
        await client.query("UPDATE identity_pim_requests SET state='active' WHERE id=$1", [id]);
      } else {
        if (['cancelled', 'revoked'].includes(current.state)) return view;
        if (current.state === 'active') await client.query('UPDATE identity_role_assignments SET revoked_at=clock_timestamp() WHERE activation_request_id=$1 AND revoked_at IS NULL', [id]);
        else if (['pending', 'approved'].includes(current.state)) await client.query("UPDATE identity_pim_requests SET state='cancelled' WHERE id=$1", [id]);
        else fail(409, 'request_terminal');
      }
      return requestView((await client.query(REQUEST_SELECT + ' WHERE request.id=$1', [id])).rows[0]);
    }, { actor: JSON.stringify(proof) }, result => action === 'activate' || ['approve', 'deny', 'revoke'].includes(action) && PROTECTED.includes(result.role)
      ? { required: true, maxAgeSeconds: 300 } : undefined);
  }
}
module.exports = { PrivilegedActivation, authority, uuid, fields, reason, duration };
