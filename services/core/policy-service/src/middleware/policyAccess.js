'use strict';

const { validContext } = require('../../../../../packages/identity-authorization-contract');
const { getPolicyPermissions, freshPolicyAuthentication, ROLE_PERMISSIONS, ALL_PERMISSIONS } = require('../../../../../packages/policy-authorization-contract');
const ROUTES = Object.freeze([
  ['POST', /^\/policies\/delivery\/frame\/?$/, 'policies.deploy'],
  ['GET', /^\/(?:policies|blueprints)\/[^/]+\/publications\/?$/, 'policies.read'],
  ['POST', /^\/(?:policies|blueprints)\/[^/]+\/publications\/?$/, 'policies.publication.request'],
  ['POST', /^\/(?:policies|blueprints)\/[^/]+\/publications\/[^/]+\/decisions\/?$/, null],
  ['GET', /^\/policies\/access\/?$/, null],
  ['GET', /^\/policies\/?$/, 'policies.read'],
  ['GET', /^\/policies\/(?:templates|conflicts|baselines|simulate)\/?$/, 'policies.read'],
  ['GET', /^\/policies\/inheritance\/[^/]+(?:\/[^/]+)?\/?$/, 'policies.read'],
  ['GET', /^\/policies\/[^/]+\/audit\/?$/, 'policies.audit.read'],
  ['GET', /^\/policies\/[^/]+\/(?:assignments|links)\/?$/, 'policies.read'],
  ['GET', /^\/policies\/[^/]+\/?$/, 'policies.read'],
  ['POST', /^\/policies\/evaluate\/?$/, 'policies.deploy'],
  ['POST', /^\/policies\/rsop\/?$/, 'policies.preview'],
  ['POST', /^\/policies\/[^/]+\/compile\/[^/]+\/?$/, 'policies.preview'],
  ['POST', /^\/policies(?:\/from-template)?\/?$/, 'policies.manage'],
  ['PUT', /^\/policies\/[^/]+\/?$/, 'policies.manage'],
  ['DELETE', /^\/policies\/[^/]+\/?$/, 'policies.manage'],
  ['POST', /^\/policies\/[^/]+\/wmi-filter\/?$/, 'policies.manage'],
  ['POST', /^\/policies\/[^/]+\/(?:activate|deactivate|assign|link)\/?$/, 'policies.deploy'],
  ['DELETE', /^\/policies\/[^/]+\/link\/[^/]+\/?$/, 'policies.deploy'],
  ['POST', /^\/policies\/baselines\/[^/]+\/apply\/?$/, 'policies.manage'],
  ['GET', /^\/update-rings\/?$/, 'policies.read'],
  ['PUT', /^\/update-rings\/[^/]+\/?$/, 'policies.manage'],
  ['POST', /^\/update-rings\/[^/]+\/assign\/?$/, 'policies.deploy'],
  ['GET', /^\/gpo(?:\/effective\/[^/]+)?\/?$/, 'policies.read'],
  ['POST', /^\/gpo\/?$/, 'policies.manage'],
  ['PUT', /^\/gpo\/[^/]+\/?$/, 'policies.manage'],
  ['DELETE', /^\/gpo\/[^/]+\/?$/, 'policies.manage'],
  ['POST', /^\/gpo\/[^/]+\/apply\/?$/, 'policies.deploy'],
  ['GET', /^\/blueprints(?:\/[^/]+(?:\/assignments)?)?\/?$/, 'policies.read'],
  ['POST', /^\/blueprints\/preview\/?$/, 'policies.preview'],
  ['POST', /^\/blueprints\/?$/, 'policies.manage'],
  ['PUT', /^\/blueprints\/[^/]+\/?$/, 'policies.manage'],
  ['DELETE', /^\/blueprints\/[^/]+\/?$/, 'policies.manage'],
  ['POST', /^\/blueprints\/[^/]+\/configurations\/?$/, 'policies.manage'],
  ['DELETE', /^\/blueprints\/[^/]+\/configurations\/[^/]+\/?$/, 'policies.manage'],
  ['POST', /^\/blueprints\/[^/]+\/(?:assign|apply)\/?$/, 'policies.deploy'],
]);

function requirePolicyAccess(req, res, next) {
  if (/^\/licenses(?:\/|$)/.test(req.path)) return next();
  res.set('Cache-Control', 'no-store');
  const operation = ROUTES.find(([method, pattern]) => req.method === method && pattern.test(req.path));
  if (!operation) return res.status(404).json({ error: 'policy_operation_not_supported' });
  if (req.user?.actor_type !== 'user' || !validContext(req.user.identity_authorization)) return res.status(403).json({ error: 'canonical_policy_operator_required' });
  req.policyPermissions = getPolicyPermissions(req.user);
  const permission = operation[2];
  if (permission && !req.policyPermissions.includes(permission)) return res.status(403).json({ error: 'forbidden', permission });
  if (!permission && /\/publications\//.test(req.path) && !['policies.publication.request', 'policies.publication.review'].some(duty => req.policyPermissions.includes(duty))) return res.status(403).json({ error: 'publication_duty_required' });
  if ((['policies.manage', 'policies.deploy', 'policies.publication.request', 'policies.publication.review'].includes(permission) || /\/publications\/.+\/decisions/.test(req.path)) && !freshPolicyAuthentication(req.user)) return res.status(428).json({ error: 'fresh_mfa_required' });
  req.policyActor = req.user.identity_authorization.userId;
  next();
}

module.exports = { getPolicyPermissions, freshPolicyAuthentication, requirePolicyAccess, ROLE_PERMISSIONS, ALL_PERMISSIONS, ROUTES };
