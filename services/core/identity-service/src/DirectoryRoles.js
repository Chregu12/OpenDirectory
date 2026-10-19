'use strict';

const { ROLES, PROTECTED } = require('../../../../packages/directory-role-contract');
const { validContext } = require('../../../../packages/identity-authorization-contract');
const { authorityTenant, lockAuthorityUsers, requireAuthorityReceiver } = require('./AuthorityTenant');
const { readRoleState } = require('./RoleState');
const { getIdentityPermissions } = require('./middleware/identityAccess');
const { acceptsRoleAuthentication } = require('../../../../packages/role-authentication-contract');
const { AuthorityCommand } = require('./AuthorityCommand');
function reject(status, message) { throw Object.assign(new Error(message), { status }); }
function identifier(value) {
  if (typeof value !== 'string' || value.length !== 36 || !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(value)) reject(400, 'Canonical UUID required');
}
function projection(row) {
  return { id: row.id, userId: row.user_id, role: row.role, reason: row.reason,
    createdAt: new Date(row.created_at).toISOString(), expiresAt: row.expires_at ? new Date(row.expires_at).toISOString() : null,
    revokedAt: row.revoked_at ? new Date(row.revoked_at).toISOString() : null, status: row.status };
}
class DirectoryRoles {
  constructor(database, options) { this.database = database; this.commands = new AuthorityCommand(database, options); }
  actor(user, target) {
    if (user?.actor_type !== 'user' || !validContext(user.identity_authorization) || typeof user.iss !== 'string' || !user.iss || typeof user.sub !== 'string' || !user.sub) reject(403, 'A canonical human operator is required');
    if (user.identity_authorization.userId.toLowerCase() === target.toLowerCase()) reject(403, 'Self-administration of roles is forbidden');
    return JSON.stringify({ issuer: user.iss, subject: user.sub, userId: user.identity_authorization.userId });
  }
  async lock(client, userId, user) {
    await requireAuthorityReceiver(client);
    const proof = { ...user.identity_authorization, issuer: user.iss, subject: user.sub };
    const tenant = await authorityTenant(client, proof, { write: true });
    await lockAuthorityUsers(client, [user.identity_authorization.userId.toLowerCase(), userId.toLowerCase()], tenant);
    await authorityTenant(client, proof);
    const state = await readRoleState(client, proof.userId);
    if (state.rolesRevision !== proof.rolesRevision || !acceptsRoleAuthentication(state.authentication, user)) reject(401, 'Role operator authority changed');
    if (!getIdentityPermissions({ roles: state.roles }).includes('identities.roles.manage')) reject(403, 'Role administration permission required');
    return state.roles;
  }
  async list(userId) {
    identifier(userId);
    return this.database.transaction(async client => {
      if (!(await client.query('SELECT id FROM users WHERE id=$1', [userId])).rows.length) reject(404, 'User not found');
      const result = await client.query(`SELECT *,CASE WHEN revoked_at IS NOT NULL THEN 'revoked'
        WHEN expires_at<=clock_timestamp() THEN 'expired'
        WHEN EXISTS(SELECT 1 FROM identity_role_review_leases review WHERE review.target_kind='assignment' AND review.target_id=identity_role_assignments.id
          AND (review.state='denied' OR review.deadline_at<=identity_role_review_now()))
          OR (activation_request_id IS NOT NULL AND NOT identity_role_review_eligible((SELECT eligibility_id FROM identity_pim_requests WHERE id=activation_request_id))) THEN 'review_expired'
        WHEN NOT EXISTS(SELECT 1 FROM identity_role_activation_policies policy WHERE policy.role=identity_role_assignments.role
          AND policy.version=policy_version AND (NOT policy.activation_required OR activation_request_id IS NOT NULL)) THEN 'policy_changed'
        ELSE 'active' END AS status FROM identity_role_assignments
        WHERE user_id=$1 ORDER BY (revoked_at IS NULL AND (expires_at IS NULL OR expires_at>clock_timestamp())) DESC,created_at DESC,id LIMIT 101`, [userId]);
      return { userId, assignments: result.rows.slice(0, 100).map(projection), truncated: result.rows.length > 100 };
    }, { readOnly: true });
  }
  async grant(userId, body, user, authorization) {
    identifier(userId); const actor = this.actor(user, userId);
    if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).some(key => !['role', 'durationSeconds', 'reason'].includes(key))
      || !ROLES.includes(body.role) || !Number.isInteger(body.durationSeconds) || body.durationSeconds < 60 || body.durationSeconds > 28800
      || typeof body.reason !== 'string' || body.reason.trim().length < 10 || body.reason.length > 500 || /[\u0000-\u001f\u007f]/.test(body.reason)) reject(400, 'A catalog role, 60–28800 seconds and a reason of 10–500 characters are required');
    if (PROTECTED.includes(body.role) && !user.roles?.includes('admin')) reject(403, 'Only a global administrator can delegate protected roles');
    return this.commands.run(user, authorization, async client => {
      const roles = await this.lock(client, userId, user);
      if (PROTECTED.includes(body.role) && !roles.includes('admin')) reject(403, 'Only a global administrator can delegate protected roles');
      const policy = (await client.query('SELECT * FROM identity_role_activation_policies WHERE role=$1 FOR SHARE',[body.role])).rows[0];
      if (!policy) reject(503,'Activation policy unavailable');
      if (policy.activation_required) reject(409,'Approved PIM activation required; direct assignment is forbidden');
      const count = (await client.query(`SELECT COUNT(*)::int AS count FROM identity_role_assignments assignment
        JOIN identity_role_activation_policies policy ON policy.role=assignment.role AND policy.version=assignment.policy_version
        WHERE user_id=$1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>clock_timestamp())
        AND NOT EXISTS(SELECT 1 FROM identity_role_review_leases review WHERE review.target_kind='assignment' AND review.target_id=assignment.id AND (review.state='denied' OR review.deadline_at<=identity_role_review_now()))
        AND (activation_request_id IS NULL OR identity_role_review_eligible((SELECT eligibility_id FROM identity_pim_requests WHERE id=activation_request_id)))`, [userId])).rows[0].count;
      if (count >= 100) reject(409, 'Active role-assignment limit reached');
      const result = await client.query(`INSERT INTO identity_role_assignments(user_id,role,reason,expires_at)
        VALUES($1,$2,$3,clock_timestamp()+$4*interval '1 second') RETURNING *, 'active' AS status`, [userId, body.role, body.reason.trim(), body.durationSeconds]);
      return projection(result.rows[0]);
    }, { actor });
  }
  async revoke(userId, assignmentId, user, authorization) {
    identifier(userId); identifier(assignmentId); const actor = this.actor(user, userId);
    return this.commands.run(user, authorization, async client => {
      const roles = await this.lock(client, userId, user);
      const current = (await client.query('SELECT * FROM identity_role_assignments WHERE user_id=$1 AND id=$2 FOR UPDATE', [userId, assignmentId])).rows[0];
      if (!current) reject(404, 'Role assignment not found');
      if (PROTECTED.includes(current.role) && !roles.includes('admin')) reject(403, 'Only a global administrator can revoke protected roles');
      if (!current.revoked_at) await client.query('UPDATE identity_role_assignments SET revoked_at=clock_timestamp() WHERE id=$1', [assignmentId]);
      return { id: assignmentId, userId, revoked: true };
    }, { actor });
  }
}
module.exports = { DirectoryRoles };
