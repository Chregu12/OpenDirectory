'use strict';

const ROLE_PERMISSIONS = {
  'application-reader': ['applications.read'],
  'application-administrator': ['applications.read', 'applications.create', 'applications.delete', 'applications.credentials.rotate'],
  'device-enrollment-operator': ['devices.enroll', 'devices.enrollment.read', 'devices.unenroll'],
  'user-lifecycle-operator': ['users.onboard', 'users.offboard'],
  'policy-deployment-operator': ['policies.deploy', 'policies.deployments.read', 'policies.rollback'],
  'compliance-reader': ['compliance.read'],
  'operations-reader': ['system.status.read'],
};

const ALL_PERMISSIONS = [...new Set([...Object.values(ROLE_PERMISSIONS).flat(),
  'applications.permissions.assign', 'devices.wipe', 'users.roles.assign', 'users.groups.assign', 'users.devices.assign'])];

const ROUTES = [
  ['GET', /^\/access\/?$/, null],
  ['GET', /^\/status\/?$/, 'system.status.read'],
  ['POST', /^\/service-principals\/?$/, 'applications.create'],
  ['GET', /^\/service-principals(?:\/[^/]+)?\/?$/, 'applications.read'],
  ['DELETE', /^\/service-principals\/[^/]+\/?$/, 'applications.delete'],
  ['POST', /^\/service-principals\/[^/]+\/rotate-secret\/?$/, 'applications.credentials.rotate'],
  ['POST', /^\/devices\/(?:enroll|bulk-enroll)\/?$/, 'devices.enroll'],
  ['GET', /^\/devices\/[^/]+\/enrollment-status\/?$/, 'devices.enrollment.read'],
  ['POST', /^\/devices\/[^/]+\/unenroll\/?$/, 'devices.unenroll'],
  ['POST', /^\/users\/onboard\/?$/, 'users.onboard'],
  ['POST', /^\/users\/[^/]+\/offboard\/?$/, 'users.offboard'],
  ['POST', /^\/policies\/deploy\/?$/, 'policies.deploy'],
  ['GET', /^\/policies\/deployments\/[^/]+\/?$/, 'policies.deployments.read'],
  ['POST', /^\/policies\/deployments\/[^/]+\/rollback\/?$/, 'policies.rollback'],
  ['GET', /^\/compliance\/snapshot\/?$/, 'compliance.read'],
];

function rolesOf(user) {
  if (user?.actor_type === 'application') return [];
  return [...(Array.isArray(user?.roles) ? user.roles : []),
    ...(Array.isArray(user?.realm_access?.roles) ? user.realm_access.roles : [])].filter(role => typeof role === 'string');
}

function isAdministrator(user) {
  return rolesOf(user).includes('admin');
}

function getQuickActionPermissions(user) {
  if (isAdministrator(user)) return [...ALL_PERMISSIONS];
  const roles = rolesOf(user);
  const permissions = Array.isArray(user?.permissions) ? user.permissions : [];
  return ALL_PERMISSIONS.filter(permission => permissions.includes(permission)
    || roles.some(role => Object.hasOwn(ROLE_PERMISSIONS, role) && ROLE_PERMISSIONS[role].includes(permission)));
}

function onboardingDepartments() {
  return (process.env.QUICK_ACTIONS_ONBOARDING_DEPARTMENTS || 'General').split(',').map(department => department.trim()).filter(Boolean);
}

function delegablePermissions(user) {
  if (isAdministrator(user)) return null;
  return [...new Set([...getQuickActionPermissions(user), ...(Array.isArray(user?.permissions) ? user.permissions : [])])]
    .filter(permission => typeof permission === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9.:_-]{0,127}$/.test(permission));
}

function requireQuickActionAccess(req, res, next) {
  if (typeof req.user?.sub !== 'string' || !req.user.sub.trim()) return res.status(401).json({ error: 'unauthorized' });
  const route = ROUTES.find(([method, pattern]) => method === req.method && pattern.test(req.path));
  if (!route) return res.status(404).json({ success: false, error: 'Not found' });
  const permissions = getQuickActionPermissions(req.user);
  req.quickActionPermissions = permissions;
  const requirePermission = permission => {
    if (permissions.includes(permission)) return true;
    res.status(403).json({ error: 'forbidden', permission });
    return false;
  };
  if (route[2] && !requirePermission(route[2])) return;
  if (req.method === 'POST' && (!req.body || Array.isArray(req.body) || typeof req.body !== 'object')) return res.status(400).json({ error: 'invalid_body' });

  if (req.method === 'POST' && /^\/service-principals\/?$/.test(req.path)) {
    const grants = req.body.permissions === undefined ? [] : req.body.permissions;
    if (!Array.isArray(grants) || grants.length > 100 || grants.some(grant => typeof grant !== 'string' || !/^[a-zA-Z0-9][a-zA-Z0-9.:_-]{0,127}$/.test(grant))) {
      return res.status(400).json({ error: 'invalid_permissions' });
    }
    if (grants.length && !requirePermission('applications.permissions.assign')) return;
    const allowedGrants = delegablePermissions(req.user);
    if (allowedGrants !== null && grants.some(grant => !allowedGrants.includes(grant))) {
      return res.status(403).json({ error: 'permission_delegation_exceeded' });
    }
  }

  if (req.method === 'POST' && /^\/devices\/[^/]+\/unenroll\/?$/.test(req.path)) {
    if (req.body.wipe !== undefined && typeof req.body.wipe !== 'boolean') return res.status(400).json({ error: 'invalid_wipe' });
    if (req.body.wipe && !requirePermission('devices.wipe')) return;
  }

  if (req.method === 'POST' && /^\/users\/onboard\/?$/.test(req.path)) {
    const role = req.body.role ?? 'standard';
    if (!['standard', 'elevated', 'admin'].includes(role)) return res.status(400).json({ error: 'invalid_role' });
    if (role !== 'standard' && !requirePermission('users.roles.assign')) return;
    const department = req.body.department === undefined || req.body.department === '' ? 'General' : req.body.department;
    if (typeof department !== 'string' || !/^[\p{L}\p{N}][\p{L}\p{N} _-]{0,63}$/u.test(department)) return res.status(400).json({ error: 'invalid_department' });
    if (!onboardingDepartments().includes(department) && !requirePermission('users.groups.assign')) return;
    if (req.body.assignDeviceId && !requirePermission('users.devices.assign')) return;
    req.body = { ...req.body, role, department };
  }
  next();
}

module.exports = { getQuickActionPermissions, requireQuickActionAccess, onboardingDepartments, delegablePermissions };
