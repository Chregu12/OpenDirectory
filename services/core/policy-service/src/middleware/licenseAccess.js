'use strict';

const ROLE_PERMISSIONS = {
  'license-reader': ['licenses.catalog.read', 'licenses.assignments.read', 'licenses.requests.read'],
  'license-manager': ['licenses.catalog.read', 'licenses.catalog.manage', 'licenses.assignments.read', 'licenses.assignments.manage', 'licenses.requests.delegate'],
  'license-approver': ['licenses.requests.read', 'licenses.requests.review'],
  'user-lifecycle-operator': ['licenses.subjects.offboard'],
};

const LEGACY_PERMISSIONS = [...new Set([...Object.values(ROLE_PERMISSIONS).flat(), 'licenses.subjects.manage', 'licenses.subjects.offboard'])];
Object.assign(ROLE_PERMISSIONS, {
  'license-scope-administrator': ['licenses.delegations.read','licenses.delegations.manage','licenses.sources.read','licenses.sources.manage'],
  'license-scope-reader': ['licenses.delegations.read','licenses.sources.read'],
  'license-delegate': ['licenses.delegations.self'],
  'license-scope-activation-reviewer': ['licenses.scopepim.review'],
  'license-scope-policy-administrator': ['licenses.scopepolicies.read','licenses.scopepolicies.manage'],
  'license-scope-policy-reader': ['licenses.scopepolicies.read'],
  'license-delegation-review-administrator': ['licenses.scopereviews.policies.read','licenses.scopereviews.policies.manage','licenses.scopereviews.all.read'],
  'license-delegation-reviewer': ['licenses.scopereviews.assigned.read','licenses.scopereviews.decide'],
  'license-delegation-review-reader': ['licenses.scopereviews.policies.read','licenses.scopereviews.all.read'],
  'license-review-administrator': ['licenses.reviews.policies.read','licenses.reviews.policies.manage','licenses.reviews.all.read'],
  'license-review-reader': ['licenses.reviews.policies.read','licenses.reviews.all.read'],
  'license-reviewer': ['licenses.reviews.assigned.read','licenses.reviews.decide'],
  'license-provider-administrator': ['licenses.fulfillment.read','licenses.fulfillment.configure','licenses.fulfillment.adopt'],
  'license-fulfillment-reader': ['licenses.fulfillment.read'],
  'license-fulfillment-operator': ['licenses.fulfillment.read','licenses.fulfillment.retry'],
});
const ALL_PERMISSIONS = [...new Set([...LEGACY_PERMISSIONS,...Object.values(ROLE_PERMISSIONS).flat()])];

function getLicensePermissions(user) {
  if(user?.actor_type==='application')return[];
  const roles = [
    ...(Array.isArray(user?.roles) ? user.roles : []),
    ...(Array.isArray(user?.realm_access?.roles) ? user.realm_access.roles : []),
  ].filter(role => typeof role === 'string');
  if (roles.includes('admin')) return ALL_PERMISSIONS.filter(permission => (permission !== 'licenses.scopepim.review' || roles.includes('license-scope-activation-reviewer'))
    && (permission !== 'licenses.sources.manage' || roles.includes('license-scope-administrator'))
    && (permission !== 'licenses.scopepolicies.manage' || roles.includes('license-scope-policy-administrator'))
    && (permission !== 'licenses.scopereviews.policies.manage' || roles.includes('license-delegation-review-administrator'))
    && (permission !== 'licenses.scopereviews.decide' || roles.includes('license-delegation-reviewer')));
  const permissions = Array.isArray(user?.permissions) ? user.permissions : [];
  return ALL_PERMISSIONS.filter(permission => roles.includes('license-administrator') && LEGACY_PERMISSIONS.includes(permission) || permissions.includes(permission)
    || (permission === 'licenses.subjects.offboard' && (permissions.includes('users.offboard') || permissions.includes('licenses.subjects.manage')))
    || roles.some(role => Object.hasOwn(ROLE_PERMISSIONS, role) && ROLE_PERMISSIONS[role].includes(permission)));
}

function requireLicenseIdentity(req, res, next) {
  if (typeof req.user?.sub !== 'string' || !req.user.sub.trim()) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  if(req.user.actor_type==='application')return res.status(403).json({error:'workload_license_administration_forbidden'});
  req.licensePermissions = getLicensePermissions(req.user);
  next();
}

function requireLicensePermission(permission) {
  return (req, res, next) => {
    if (!req.licensePermissions?.includes(permission)) {
      return res.status(403).json({ error: 'forbidden', permission });
    }
    next();
  };
}

function isOwnLicenseRequest(userId, request) {
  return request.requester_id === userId
    || (request.assignee_type === 'user' && request.assignee_id === userId);
}

module.exports = { getLicensePermissions, requireLicenseIdentity, requireLicensePermission, isOwnLicenseRequest };
