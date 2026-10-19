'use strict';

const { hasAdminAccess } = require('./oidcAuth');
const { getPolicyPermissions, freshPolicyAuthentication } = require('../../../../../packages/policy-authorization-contract');
function requirePolicyDeviceAccess(kind) {
  if (!['inventory', 'command', 'protocol'].includes(kind)) throw new Error('Fixed policy device operation required');
  return (req, res, next) => {
    const governed = kind === 'protocol' || kind === 'command' && req.body?.command === 'update_policy';
    if (!governed && (req.internalService === true || hasAdminAccess(req.user))) return next();
    if (!getPolicyPermissions(req.user).includes('policies.deploy')) return res.status(403).json({ error: 'policy_device_operation_forbidden' });
    if (!freshPolicyAuthentication(req.user)) return res.status(428).json({ error: 'fresh_mfa_required' });
    if (kind === 'command' && req.body?.command !== 'update_policy') return res.status(403).json({ error: 'policy_device_command_forbidden' });
    req.policyDeviceOperator = true; res.set('Cache-Control', 'no-store'); next();
  };
}
function policyDeviceView(req, device) {
  return req.policyDeviceOperator ? { id: typeof device.id === 'string' ? device.id : null,
    hostname: typeof device.hostname === 'string' ? device.hostname : null, platform: typeof device.platform === 'string' ? device.platform : null } : device;
}
module.exports = { requirePolicyDeviceAccess, policyDeviceView };
