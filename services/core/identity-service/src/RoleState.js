'use strict';

const { createHash } = require('crypto');
const { ROLES, MFA_LOCKED_ROLES, validRoles } = require('../../../../packages/directory-role-contract');
const { validRevision } = require('../../../../packages/identity-authorization-contract');
const { ownerState } = require('./CompanyOwner');
const {employeeBinding}=require('./EmployeeBinding');
function validPolicy(row) {
  if (!row || !ROLES.includes(row.role) || !validRevision(String(row.version)) || typeof row.mfa_required !== 'boolean'
    || !Number.isInteger(row.max_age_seconds) || row.max_age_seconds < 300 || row.max_age_seconds > 86400
    || MFA_LOCKED_ROLES.includes(row.role) && (!row.mfa_required || row.max_age_seconds !== 300)) {
    throw Object.assign(new Error('authentication_policy_unavailable'), { status: 503, code: 'authentication_policy_unavailable' });
  }
  return row;
}
async function readRoleState(client, userId, { delegateEvidence = false, scopeReviewerEvidence = false, publicationEvidence = false } = {}) {
  const grants = (await client.query(`SELECT assignment.id,assignment.role,assignment.policy_version,assignment.activation_request_id,
    policy.version AS activation_version,policy.activation_required,policy.max_duration_seconds,review.id AS review_id,review.version AS review_version,
    eligible_review.id AS eligibility_review_id,eligible_review.version AS eligibility_review_version FROM identity_role_assignments assignment
    LEFT JOIN identity_role_activation_policies policy ON policy.role=assignment.role
    LEFT JOIN identity_role_review_leases review ON review.target_kind='assignment' AND review.target_id=assignment.id
    LEFT JOIN identity_pim_requests request ON request.id=assignment.activation_request_id
    LEFT JOIN identity_role_review_leases eligible_review ON eligible_review.target_kind='eligibility' AND eligible_review.target_id=request.eligibility_id
    WHERE assignment.user_id=$1
    AND assignment.revoked_at IS NULL AND (assignment.expires_at IS NULL OR assignment.expires_at>clock_timestamp())
    AND (policy.role IS NULL OR assignment.policy_version=policy.version AND (NOT policy.activation_required OR assignment.activation_request_id IS NOT NULL))
    AND (review.id IS NULL OR review.state<>'denied' AND (review.deadline_at IS NULL OR review.deadline_at>identity_role_review_now()))
    AND (eligible_review.id IS NULL OR eligible_review.state<>'denied' AND (eligible_review.deadline_at IS NULL OR eligible_review.deadline_at>identity_role_review_now()))
    ORDER BY assignment.id LIMIT 101`, [userId])).rows;
  const held = [...new Set(grants.map(grant => grant.role))].sort();
  if (grants.length > 100 || !validRoles(held) || grants.some(grant => !validRevision(String(grant.policy_version))
    || !validRevision(String(grant.activation_version)) || typeof grant.activation_required !== 'boolean'
    || !Number.isInteger(grant.max_duration_seconds) || grant.max_duration_seconds < 60 || grant.max_duration_seconds > 28800)) throw new Error('Invalid canonical role state');
  const roles = [...new Set(grants.filter(grant => String(grant.policy_version) === String(grant.activation_version)
    && (!grant.activation_required || grant.activation_request_id)).map(grant => grant.role))].sort();
  const policies = (await client.query('SELECT * FROM identity_role_authentication WHERE role=ANY($1::text[]) ORDER BY role COLLATE "C"', [held])).rows;
  if (policies.length !== held.length || policies.some((policy, index) => validPolicy(policy).role !== held[index])) throw new Error('Invalid canonical authentication policy');
  const required = policies.filter(policy => roles.includes(policy.role) && policy.mfa_required);
  const result = { roles, authentication: { required: required.length > 0, maxAgeSeconds: Math.min(86400, ...required.map(policy => policy.max_age_seconds)) },
    rolesRevision: createHash('sha256').update(JSON.stringify([grants.map(grant => [grant.id, grant.role, String(grant.policy_version), String(grant.activation_version),
      ...(grant.review_id || grant.eligibility_review_id ? [grant.review_id || null,grant.review_version ? String(grant.review_version) : null,grant.eligibility_review_id || null,grant.eligibility_review_version ? String(grant.eligibility_review_version) : null] : [])]), policies.map(policy => [policy.role, String(policy.version)])])).digest('hex') };
  const owner = await ownerState(client, userId);
  if (owner?.active) {
    result.authentication = { required: true, maxAgeSeconds: 300 };
    result.rolesRevision = createHash('sha256').update(JSON.stringify(['company-owner-v1', result.rolesRevision, owner.id, owner.tenant_id])).digest('hex');
  } else {
    const employee=await employeeBinding(client,userId);
    if(employee){
      if(!employee.active)throw Object.assign(new Error('employee_binding_changed'),{status:401,code:'employee_binding_changed'});
      result.authentication={required:true,maxAgeSeconds:result.authentication.maxAgeSeconds};
      result.rolesRevision=createHash('sha256').update(JSON.stringify(['company-employee-v1',result.rolesRevision,employee.binding])).digest('hex');
      result.employeeBinding=employee.binding;
    }
  }
  if (delegateEvidence) result.delegationRevision = roles.includes('license-delegate') ? createHash('sha256').update(JSON.stringify(['license-delegate-v1',
    grants.filter(grant => grant.role === 'license-delegate').map(grant => [grant.id,String(grant.policy_version),String(grant.activation_version),
      grant.review_id || null,grant.review_version ? String(grant.review_version) : null,grant.eligibility_review_id || null,grant.eligibility_review_version ? String(grant.eligibility_review_version) : null]),
    policies.filter(policy => policy.role === 'license-delegate').map(policy => String(policy.version))])).digest('hex') : null;
  if (scopeReviewerEvidence) result.scopeReviewerRevision = roles.includes('license-scope-activation-reviewer') ? createHash('sha256').update(JSON.stringify(['license-scope-activation-reviewer-v1',
    grants.filter(grant => grant.role === 'license-scope-activation-reviewer').map(grant => [grant.id,String(grant.policy_version),String(grant.activation_version),
      grant.review_id || null,grant.review_version ? String(grant.review_version) : null,grant.eligibility_review_id || null,grant.eligibility_review_version ? String(grant.eligibility_review_version) : null]),
    policies.filter(policy => policy.role === 'license-scope-activation-reviewer').map(policy => String(policy.version))])).digest('hex') : null;
  if (publicationEvidence) {
    for (const [field, duties] of [['publicationRequestRevision', ['admin', 'policy-administrator']], ['publicationReviewRevision', ['policy-publication-reviewer']]]) {
      const relevant = grants.filter(grant => roles.includes(grant.role) && duties.includes(grant.role));
      result[field] = relevant.length ? createHash('sha256').update(JSON.stringify(['policy-publication-authority-v1', field,
        relevant.map(grant => [grant.id, grant.role, String(grant.policy_version), String(grant.activation_version), grant.review_id || null,
          grant.review_version ? String(grant.review_version) : null, grant.eligibility_review_id || null, grant.eligibility_review_version ? String(grant.eligibility_review_version) : null]),
        policies.filter(policy => duties.includes(policy.role)).map(policy => [policy.role, String(policy.version)])])).digest('hex') : null;
    }
  }
  return result;
}
module.exports = { readRoleState, validPolicy };
