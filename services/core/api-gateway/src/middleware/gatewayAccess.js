'use strict';

const PERMISSIONS = ['gateway.status.read', 'gateway.config.read', 'gateway.config.manage', 'gateway.keys.read', 'gateway.keys.manage',
  'gateway.webhooks.read', 'gateway.webhooks.manage', 'gateway.events.read'];
const ROLE_PERMISSIONS = {
  'gateway-reader': ['gateway.status.read', 'gateway.config.read', 'gateway.webhooks.read', 'gateway.events.read'],
  'gateway-administrator': PERMISSIONS,
  'gateway-key-administrator': ['gateway.keys.read', 'gateway.keys.manage'],
  'gateway-webhook-administrator': ['gateway.webhooks.read', 'gateway.webhooks.manage'],
};
const OPERATIONS = [
  ['GET', /^\/api\/gateway\/access\/?$/, null],
  ['GET', /^\/(?:health\/detailed|api\/gateway\/(?:info|routes)|api\/services(?:\/[^/]+\/health)?)\/?$/, 'gateway.status.read'],
  ['GET', /^\/api\/config\/modules\/?$/, 'gateway.config.read'],
  ['POST', /^\/api\/config\/modules\/[^/]+\/?$/, 'gateway.config.manage'],
  ['GET', /^\/api\/(?:admin\/keys|gateway\/api-keys)\/?$/, 'gateway.keys.read'],
  ['POST', /^\/api\/(?:admin\/keys|gateway\/api-keys)\/?$/, 'gateway.keys.manage'],
  ['DELETE', /^\/api\/(?:admin\/keys|gateway\/api-keys)\/[^/]+\/?$/, 'gateway.keys.manage'],
  ['GET', /^\/api\/gateway\/webhooks(?:\/[^/]+\/deliveries)?\/?$/, 'gateway.webhooks.read'],
  ['POST', /^\/api\/gateway\/webhooks(?:\/[^/]+\/test)?\/?$/, 'gateway.webhooks.manage'],
  ['PUT', /^\/api\/gateway\/webhooks\/[^/]+\/?$/, 'gateway.webhooks.manage'],
  ['DELETE', /^\/api\/gateway\/webhooks\/[^/]+\/?$/, 'gateway.webhooks.manage'],
];
const DELEGATED = /^\/api\/(?:devices|licenses|license|license-groups|license-users|license-reviewers|license-delegates|license-activation-reviewers|license-scope-reviewers|identity|users|groups|ous|quick|policies|blueprints|company-blueprints|company-blueprint-assignments|gpo|update-rings)(?:\/|$)/;

function roles(user) { return [...(Array.isArray(user?.roles) ? user.roles : []), ...(Array.isArray(user?.realm_access?.roles) ? user.realm_access.roles : [])].filter(role => typeof role === 'string'); }
function getGatewayPermissions(user) {
  const grantedRoles = roles(user); const grants = Array.isArray(user?.permissions) ? user.permissions : [];
  if (grantedRoles.includes('admin')) return [...PERMISSIONS];
  return PERMISSIONS.filter(permission => grants.includes(permission) || grantedRoles.some(role => Object.hasOwn(ROLE_PERMISSIONS, role) && ROLE_PERMISSIONS[role].includes(permission)));
}
function isPublic(req) {
  if (req.method === 'OPTIONS') return true;
  if (req.method === 'GET' && ['/health', '/health/live', '/docs', '/api-docs', '/docs/openapi.json'].includes(req.path)) return true;
  return req.method === 'POST' && ['/api/auth/login', '/api/auth/register'].includes(req.path);
}
function gatewayAccess(resolveProxy) {
  return (req, res, next) => {
    if (isPublic(req)) return next();
    req.gatewayPermissions = getGatewayPermissions(req.user);
    const operation = OPERATIONS.find(([method, pattern]) => req.method === method && pattern.test(req.path));
    if (operation) {
      if (operation[2] && !req.gatewayPermissions.includes(operation[2])) return res.status(403).json({ error: 'forbidden', permission: operation[2] });
      return next();
    }
    if (/^\/api\/(?:gateway|admin|services|config\/modules)(?:\/|$)/.test(req.path) || req.path.startsWith('/health')) return res.status(404).json({ error: 'Gateway operation not found' });
    const proxy = resolveProxy(req.path);
    if (DELEGATED.test(req.path)) return next();
    const permission = proxy ? `gateway.proxies.${proxy.name}.access` : null;
    if (!proxy && !roles(req.user).includes('admin')) return res.status(403).json({ error: 'Unregistered backend operation denied' });
    if (!roles(req.user).includes('admin') && !(permission && Array.isArray(req.user?.permissions) && req.user.permissions.includes(permission))) return res.status(403).json({ error: 'forbidden', permission });
    next();
  };
}

module.exports = { getGatewayPermissions, gatewayAccess, isPublic, roles, OPERATIONS };
