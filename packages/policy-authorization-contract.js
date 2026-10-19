'use strict';

const { validContext } = require('./identity-authorization-contract');
const { acceptsRoleAuthentication } = require('./role-authentication-contract');
const READ = ['policies.read', 'policies.preview', 'policies.audit.read'];
const ROLE_PERMISSIONS = Object.freeze({
  'policy-reader': Object.freeze([...READ]),
  'policy-deployment-operator': Object.freeze([...READ, 'policies.deploy']),
  'policy-administrator': Object.freeze([...READ, 'policies.manage', 'policies.deploy', 'policies.publication.request']),
  'policy-publication-reviewer': Object.freeze([...READ, 'policies.publication.review']),
});
const ALL_PERMISSIONS = Object.freeze([...new Set(Object.values(ROLE_PERMISSIONS).flat())]);
function getPolicyPermissions(user) {
  if (user?.actor_type !== 'user' || !validContext(user.identity_authorization)) return [];
  const roles = Array.isArray(user.roles) ? user.roles : [];
  if (roles.includes('admin')) return ALL_PERMISSIONS.filter(permission => permission !== 'policies.publication.review' || roles.includes('policy-publication-reviewer'));
  return ALL_PERMISSIONS.filter(permission => roles.some(role => typeof role === 'string' && Object.hasOwn(ROLE_PERMISSIONS, role) && ROLE_PERMISSIONS[role].includes(permission)));
}
function freshPolicyAuthentication(user) {
  return acceptsRoleAuthentication({ required: true, maxAgeSeconds: 300 }, user);
}
module.exports = { getPolicyPermissions, freshPolicyAuthentication, ROLE_PERMISSIONS, ALL_PERMISSIONS };
