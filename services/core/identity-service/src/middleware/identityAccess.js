'use strict';
const {SOURCE_SCOPE}=require('../../../../../packages/group-license-lease-contract');
const {COMPANY_DIRECTORY_PERMISSIONS}=require('../CompanyOwner');

const ROLE_PERMISSIONS = {
  'policy-administrator': ['policies.publication-actors.read'],
  'policy-deployment-operator': ['policies.publication-actors.read'],
  'policy-publication-reviewer': ['policies.publication-actors.read'],
  'directory-reader': ['users.read', 'groups.read', 'ous.read'],
  'user-administrator': ['users.read', 'users.create', 'users.update', 'users.status.manage'],
  'user-lifecycle-operator': ['users.read', 'users.create', 'users.update', 'users.status.manage'],
  'group-administrator': ['groups.read', 'groups.create', 'groups.update', 'groups.delete', 'groups.members.manage'],
  'ou-administrator': ['ous.read', 'ous.create', 'ous.update', 'ous.delete', 'ous.members.manage'],
  'license-group-reader': ['licenses.groups.read'],
  'license-eligibility-reader': ['licenses.users.read'],
  'license-manager': ['licenses.groups.read', 'licenses.users.read'],
  'license-administrator': ['licenses.groups.read', 'licenses.users.read'],
  'license-approver': ['licenses.groups.read', 'licenses.users.read'],
  'session-administrator': ['users.sessions.invalidate'],
  'user-profile-editor': ['users.read', 'users.update'],
  'role-reader': ['identities.roles.read'],
  'role-administrator': ['identities.roles.read', 'identities.roles.manage'],
  'pim-administrator': ['pim.eligibilities.read', 'pim.eligibilities.manage'],
  'pim-approver': ['pim.requests.read', 'pim.requests.review', 'pim.activations.revoke'],
  'pim-reader': ['pim.eligibilities.read', 'pim.requests.read'],
  'authentication-policy-reader': ['authentication.policies.read'],
  'authentication-policy-administrator': ['authentication.policies.read', 'authentication.policies.manage'],
  'license-provider-administrator': ['licenses.users.read'],
  'privileged-access-policy-reader': ['pim.policies.read'],
  'privileged-access-policy-administrator': ['pim.policies.read', 'pim.policies.manage'],
  'access-review-administrator': ['reviews.policies.read', 'reviews.policies.manage', 'reviews.all.read'],
  'access-review-reader': ['reviews.policies.read', 'reviews.all.read'],
  'access-reviewer': ['reviews.assigned.read', 'reviews.decide'],
  'license-review-administrator': ['licenses.reviewers.read', 'licenses.users.read', 'licenses.groups.read'],
  'license-reviewer': ['licenses.users.read', 'licenses.groups.read'],
  'license-scope-administrator': ['licenses.delegates.read', 'licenses.activation-reviewers.read','licenses.sources.read','licenses.sources.manage'],
  'license-scope-reader': ['licenses.sources.read'],
  'license-scope-activation-reviewer': ['licenses.delegates.read'],
  'license-scope-policy-administrator': ['licenses.delegates.read','licenses.activation-reviewers.read'],
  'license-delegation-review-administrator': ['licenses.scope-reviewers.read'],
  'license-delegation-reviewer': ['licenses.delegates.read'],
  'group-review-administrator': ['groups.reviews.policies.read','groups.reviews.policies.manage','groups.reviews.all.read'],
  'group-reviewer': ['groups.reviews.assigned.read','groups.reviews.decide'],
  'group-review-reader': ['groups.reviews.policies.read','groups.reviews.all.read'],
  'license-delegate': ['licenses.users.read', 'licenses.groups.read', 'licenses.activation-reviewers.read'],
};
const ALL_PERMISSIONS = [...new Set([...Object.values(ROLE_PERMISSIONS).flat(), 'users.delete', 'identities.links.manage', 'organization.read', 'organization.manage', 'organization.delegations.manage'])];
const ROUTES = [
  ['GET', /^\/users\/[a-f0-9-]{36}\/company-offboarding-groups(?:\/history)?$/, []],
  ['POST', /^\/users\/[a-f0-9-]{36}\/company-offboarding-groups$/, []],
  ['GET', /^\/users\/[a-f0-9-]{36}\/company-offboarding-access(?:\/(?:capabilities|history))?$/, []],
  ['POST', /^\/users\/[a-f0-9-]{36}\/company-offboarding-access$/, []],
  ['POST', /^\/users\/[a-f0-9-]{36}\/company-offboarding$/, []],
  ['GET', /^\/identity\/company-licenses\/?$/, []],
  ['POST', /^\/identity\/company-licenses\/?$/, []],
  ['GET', /^\/identity\/company-blueprints\/?$/, []],
  ['GET', /^\/identity\/device-inventory\/?$/, []],
  ['POST', /^\/identity\/device-inventory\/?$/, []],
  ['POST', /^\/identity\/device-offboarding\/?$/, []],
  ['GET', /^\/identity\/company-registrations(?:\/[a-f0-9-]{36})?\/?$/, ['company.registrations.review']],
  ['POST', /^\/identity\/company-registrations\/[a-f0-9-]{36}\/review\/?$/, ['company.registrations.review']],
  ['GET', /^\/identity\/organization\/delegations\/?$/, ['organization.delegations.manage']],
  ['POST', /^\/identity\/organization\/delegations(?:\/[a-f0-9-]{36}\/revoke)?\/?$/, ['organization.delegations.manage']],
  ['GET', /^\/identity\/organization\/?$/, ['organization.read']],
  ['PUT', /^\/identity\/organization\/?$/, ['organization.manage']],
  ['GET', /^\/policy-publication-actors\/[^/]+\/snapshot\/?$/, ['policies.publication-actors.read']],
  ['GET', /^\/identity\/license-sources\/(?:groups|clients)\/[^/]+\/?$/, ['licenses.sources.read']],
  ['GET', /^\/identity\/license-sources\/[^/]+\/?$/, ['licenses.sources.read']],
  ['POST', /^\/identity\/license-sources\/?$/, ['licenses.sources.manage']],
  ['POST', /^\/identity\/license-sources\/[^/]+\/revoke\/?$/, ['licenses.sources.manage']],
  ['GET', /^\/identity\/membership-reviews\/policies\/groups\/[^/]+\/?$/, ['groups.reviews.policies.read']],
  ['POST', /^\/identity\/membership-reviews\/policies\/?$/, ['groups.reviews.policies.manage']],
  ['POST', /^\/identity\/membership-reviews\/policies\/[^/]+\/retire\/?$/, ['groups.reviews.policies.manage']],
  ['GET', /^\/identity\/membership-reviews\/assigned\/?$/, ['groups.reviews.assigned.read']],
  ['GET', /^\/identity\/membership-reviews\/(?:self|[^/]+)\/?$/, []],
  ['POST', /^\/identity\/membership-reviews\/[^/]+\/decisions\/?$/, ['groups.reviews.decide']],
  ['GET', /^\/license-delegates\/[^/]+\/snapshot\/?$/, []],
  ['GET', /^\/license-activation-reviewers\/[^/]+\/snapshot\/?$/, []],
  ['GET', /^\/license-reviewers\/[^/]+\/snapshot\/?$/, ['licenses.reviewers.read']],
  ['GET', /^\/license-scope-reviewers\/[^/]+\/snapshot\/?$/, ['licenses.scope-reviewers.read']],
  ['GET', /^\/identity\/access\/?$/, []],
  ['GET', /^\/identity\/subject\/?$/, []],
  ['GET', /^\/identity\/reviews\/policies\/[^/]+\/?$/, ['reviews.policies.read']],
  ['POST', /^\/identity\/reviews\/policies\/?$/, ['reviews.policies.manage']],
  ['POST', /^\/identity\/reviews\/policies\/[^/]+\/retire\/?$/, ['reviews.policies.manage']],
  ['GET', /^\/identity\/reviews\/(?:self|[^/]+)\/?$/, []],
  ['POST', /^\/identity\/reviews\/[^/]+\/decisions\/?$/, ['reviews.decide']],
  ['GET', /^\/identity\/authentication\/roles\/[^/]+\/?$/, ['authentication.policies.read']],
  ['PUT', /^\/identity\/authentication\/roles\/[^/]+\/?$/, ['authentication.policies.manage']],
  ['GET', /^\/identity\/pim\/(?:catalog|self)\/?$/, []],
  ['GET', /^\/identity\/pim\/policies\/[^/]+\/?$/, ['pim.policies.read']],
  ['PUT', /^\/identity\/pim\/policies\/[^/]+\/?$/, ['pim.policies.manage']],
  ['GET', /^\/identity\/pim\/eligibilities\/?$/, ['pim.eligibilities.read']],
  ['POST', /^\/identity\/pim\/eligibilities\/?$/, ['pim.eligibilities.manage']],
  ['DELETE', /^\/identity\/pim\/eligibilities\/[^/]+\/?$/, ['pim.eligibilities.manage']],
  ['GET', /^\/identity\/pim\/requests\/?$/, ['pim.requests.read']],
  ['POST', /^\/identity\/pim\/requests\/?$/, []],
  ['POST', /^\/identity\/pim\/requests\/[^/]+\/(?:activate|cancel)\/?$/, []],
  ['POST', /^\/identity\/pim\/requests\/[^/]+\/(?:approve|deny)\/?$/, ['pim.requests.review']],
  ['POST', /^\/identity\/pim\/requests\/[^/]+\/revoke\/?$/, ['pim.activations.revoke']],
  ['GET', /^\/identity\/roles\/catalog\/?$/, ['identities.roles.read']],
  ['GET', /^\/users\/[^/]+\/roles\/?$/, ['identities.roles.read']],
  ['POST', /^\/users\/[^/]+\/roles\/?$/, ['identities.roles.manage']],
  ['DELETE', /^\/users\/[^/]+\/roles\/[^/]+\/?$/, ['identities.roles.manage']],
  ['POST', /^\/identity\/links\/?$/, ['identities.links.manage']],
  ['DELETE', /^\/identity\/links\/?$/, ['identities.links.manage']],
  ['GET', /^\/identity\/search\/?$/, ['users.read', 'groups.read']],
  ['GET', /^\/license-groups\/[^/]+\/snapshot\/?$/, ['licenses.groups.read']],
  ['GET', /^\/license-users\/[^/]+\/snapshot\/?$/, []],
  ['GET', /^\/users(?:\/[^/]+)?\/?$/, ['users.read']],
  ['POST', /^\/users\/?$/, ['users.create']],
  ['PUT', /^\/users\/[^/]+\/?$/, ['users.update']],
  ['DELETE', /^\/users\/[^/]+\/?$/, ['users.delete']],
  ['POST', /^\/users\/[^/]+\/authorization\/invalidate\/?$/, ['users.sessions.invalidate']],
  ['GET', /^\/groups(?:\/[^/]+)?\/?$/, ['groups.read']],
  ['POST', /^\/groups\/?$/, ['groups.create']],
  ['PUT', /^\/groups\/[^/]+\/?$/, ['groups.update']],
  ['DELETE', /^\/groups\/[^/]+\/?$/, ['groups.delete']],
  ['POST', /^\/groups\/[^/]+\/members\/?$/, ['groups.members.manage']],
  ['DELETE', /^\/groups\/[^/]+\/members\/[^/]+\/?$/, ['groups.members.manage']],
  ['GET', /^\/ous\/[^/]+\/members\/?$/, ['ous.read']],
  ['POST', /^\/ous\/[^/]+\/members\/?$/, ['ous.members.manage']],
  ['DELETE', /^\/ous\/[^/]+\/members\/[^/]+\/?$/, ['ous.members.manage']],
  ['GET', /^\/ous(?:\/[^/]+)?\/?$/, ['ous.read']],
  ['POST', /^\/ous\/?$/, ['ous.create']],
  ['PUT', /^\/ous\/[^/]+\/?$/, ['ous.update']],
  ['DELETE', /^\/ous\/[^/]+\/?$/, ['ous.delete']],
];

function getIdentityPermissions(user) {
  if(user?.actor_type==='application')return Array.isArray(user.permissions)&&user.permissions.includes('licenses.users.read')?['licenses.users.read']:[];
  const roles = [...(Array.isArray(user?.roles) ? user.roles : []), ...(Array.isArray(user?.realm_access?.roles) ? user.realm_access.roles : [])];
  if (roles.includes('admin')) return ALL_PERMISSIONS.filter(permission=>permission!=='groups.reviews.policies.manage'||roles.includes('group-review-administrator')).filter(permission=>permission!=='groups.reviews.decide'||roles.includes('group-reviewer')).filter(permission=>permission!=='licenses.sources.manage'||roles.includes('license-scope-administrator'));
  const permissions = Array.isArray(user?.permissions) ? user.permissions : [];
  return ALL_PERMISSIONS.filter(permission => permissions.includes(permission)
    || roles.some(role => typeof role === 'string' && Object.hasOwn(ROLE_PERMISSIONS, role) && ROLE_PERMISSIONS[role].includes(permission)));
}

function requireIdentityAccess(req, res, next) {
  if (typeof req.user?.sub !== 'string' || !req.user.sub.trim()) return res.status(401).json({ error: 'unauthorized' });
  if(req.user.actor_type==='application'&&req.user.scope===SOURCE_SCOPE&&JSON.stringify(req.user.permissions)===JSON.stringify([SOURCE_SCOPE])&&req.method==='GET'&&/^\/license-groups\/[a-f0-9-]{36}\/snapshot$/.test(req.path)){
    if(Object.keys(req.query).length||Object.keys(req.body||{}).length||req.headers['x-api-key'])return res.status(400).json({error:'exact_workload_source_path_required'});req.identityPermissions=[];req.groupSourceWorkload=true;return next();
  }
  if(req.user.actor_type==='application'&&!(req.method==='GET'&&/^\/license-users\/[a-f0-9-]{36}\/snapshot$/.test(req.path)&&req.user.scope==='licenses.users.read'&&JSON.stringify(req.user.permissions)===JSON.stringify(['licenses.users.read'])))return res.status(403).json({error:'workload_purpose_forbidden'});
  const route = ROUTES.find(([method, pattern]) => req.method === method && pattern.test(req.path));
  if (!route) return res.status(404).json({ error: 'Not found' });
  req.identityPermissions = [...new Set([...getIdentityPermissions(req.user), ...(req.organizationPermissions || []).filter(permission => ['organization.read', 'organization.manage', 'organization.delegations.manage'].includes(permission)),
    ...(req.companyRegistrationPermissions || []).filter(permission => permission === 'company.registrations.review'),
    ...(req.companyDirectoryPermissions || []).filter(permission => COMPANY_DIRECTORY_PERMISSIONS.includes(permission))])];
  const required = [...route[2]];
  if (req.method === 'PUT' && /^\/users\/[^/]+\/?$/.test(req.path) && Object.hasOwn(req.body || {}, 'enabled')) required.push('users.status.manage');
  const missing = required.find(permission => !req.identityPermissions.includes(permission));
  if (missing) return res.status(403).json({ error: 'forbidden', permission: missing });
  next();
}

module.exports = { getIdentityPermissions, requireIdentityAccess };
