'use strict';

const ROLES = Object.freeze([
  'admin', 'role-administrator', 'role-reader', 'user', 'directory-reader', 'user-administrator', 'user-lifecycle-operator',
  'user-profile-editor', 'group-administrator', 'ou-administrator', 'session-administrator', 'license-reader', 'license-manager',
  'license-administrator', 'license-approver', 'license-group-reader', 'license-eligibility-reader', 'application-reader',
  'application-administrator', 'device-enrollment-operator', 'policy-deployment-operator', 'compliance-reader', 'operations-reader',
  'gateway-reader', 'gateway-administrator', 'gateway-key-administrator', 'gateway-webhook-administrator',
  'pim-administrator', 'pim-approver', 'pim-reader',
  'application-access-administrator', 'application-access-reader',
  'application-authentication-administrator', 'application-authentication-reader',
  'authentication-policy-administrator', 'authentication-policy-reader',
  'license-provider-administrator', 'license-fulfillment-reader', 'license-fulfillment-operator',
  'privileged-access-policy-administrator', 'privileged-access-policy-reader',
  'access-review-administrator', 'access-reviewer', 'access-review-reader',
  'license-review-administrator', 'license-reviewer', 'license-review-reader',
  'license-scope-administrator', 'license-delegate', 'license-scope-reader',
  'license-scope-activation-reviewer',
  'license-scope-policy-administrator', 'license-scope-policy-reader',
  'license-delegation-review-administrator', 'license-delegation-reviewer', 'license-delegation-review-reader',
  'group-review-administrator', 'group-reviewer', 'group-review-reader',
  'policy-reader', 'policy-administrator', 'policy-publication-reviewer',
]);
const PROTECTED = Object.freeze(['admin', 'role-administrator', 'pim-administrator', 'pim-approver', 'application-authentication-administrator', 'authentication-policy-administrator', 'license-provider-administrator', 'license-fulfillment-operator', 'privileged-access-policy-administrator', 'access-review-administrator', 'access-reviewer', 'license-review-administrator', 'license-reviewer', 'license-scope-administrator', 'license-delegate', 'license-scope-activation-reviewer', 'license-scope-policy-administrator', 'license-delegation-review-administrator', 'license-delegation-reviewer', 'group-review-administrator', 'group-reviewer', 'policy-administrator', 'policy-publication-reviewer']);
const MFA_LOCKED_ROLES = Object.freeze(['authentication-policy-administrator', 'privileged-access-policy-administrator', 'access-review-administrator', 'access-reviewer', 'license-review-administrator', 'license-reviewer', 'license-scope-administrator', 'license-delegate', 'license-scope-activation-reviewer', 'license-scope-policy-administrator', 'license-delegation-review-administrator', 'license-delegation-reviewer', 'group-review-administrator', 'group-reviewer', 'policy-administrator', 'policy-publication-reviewer']);
function validRoles(value) {
  return Array.isArray(value) && value.length <= ROLES.length && value.every(role => ROLES.includes(role))
    && value.every((role, index) => index === 0 || value[index - 1] < role);
}
function rolePermissions(roles) {
  return roles.includes('user-profile-editor') ? ['users.read', 'users.update'] : [];
}
module.exports = { ROLES, PROTECTED, MFA_LOCKED_ROLES, validRoles, rolePermissions };
