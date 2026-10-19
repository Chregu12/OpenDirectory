'use strict';

const { randomUUID } = require('node:crypto');
const { requirePolicyDeviceAccess, policyDeviceView } = require('../middleware/policyDeviceAccess');
function actor(roles = ['policy-deployment-operator'], fresh = true) {
  const userId = randomUUID(); const authTime = Math.floor(Date.now() / 1000);
  return { actor_type: 'user', roles, identity_authorization: { userId, revision: '1', linkRevision: '1', rolesRevision: 'a'.repeat(64) },
    ...(fresh ? { auth_time: authTime, amr: ['pwd', 'otp'], mfa_authorization: { schemaVersion: 1, userId, revision: '1', methods: ['pwd', 'otp'], authTime } } : {}) };
}
function invoke(kind, user, body = {}) {
  const req = { user, body }; const res = { set: jest.fn().mockReturnThis(), status: jest.fn().mockReturnThis(), json: jest.fn() }; const next = jest.fn();
  requirePolicyDeviceAccess(kind)(req, res, next); return { req, res, next };
}
test.each(['wipe', 'lock', 'unlock', 'restart', 'install_app', 'uninstall_app', 'run_av_scan', 'collect_logs'])('a policy deployer cannot issue %s commands', command => {
  const current = invoke('command', actor(), { command }); expect(current.res.status).toHaveBeenCalledWith(403); expect(current.next).not.toHaveBeenCalled();
});
test.each(['user', 'policy-reader', 'license-manager', 'application-administrator'])('%s has no delegated policy device delivery', role => {
  expect(invoke('inventory', actor([role])).res.status).toHaveBeenCalledWith(403);
});
test('internal credentials and application-like administrator aliases cannot bypass the policy command contract',()=>{
 const req={internalService:true,body:{command:'update_policy'}};const res={status:jest.fn().mockReturnThis(),json:jest.fn().mockReturnThis(),set:jest.fn().mockReturnThis()};const next=jest.fn();requirePolicyDeviceAccess('command')(req,res,next);expect(res.status).toHaveBeenCalledWith(403);expect(next).not.toHaveBeenCalled();
 const application={...actor(['admin']),actor_type:'application'};expect(invoke('command',application,{command:'update_policy'}).res.status).toHaveBeenCalledWith(403);
});
test('a narrowly delegated policy deployer receives only the fixed inventory projection and update-policy purpose', () => {
  const current = invoke('inventory', actor()); expect(current.next).toHaveBeenCalledTimes(1);
  expect(policyDeviceView(current.req, { id: 'device', hostname: 'test', platform: 'windows', token: 'never-disclose', data: { password: 'never-disclose' } })).toEqual({ id: 'device', hostname: 'test', platform: 'windows' });
  expect(invoke('command', actor(), { command: 'update_policy' }).next).toHaveBeenCalledTimes(1);
});
test('application role-looking claims and stale or unbound factors cannot borrow this human purpose', () => {
  expect(invoke('inventory', { ...actor(), actor_type: 'application' }).res.status).toHaveBeenCalledWith(403);
  expect(invoke('inventory', actor(['policy-deployment-operator'], false)).res.status).toHaveBeenCalledWith(428);
  const aged = actor(); aged.auth_time -= 301; aged.mfa_authorization.authTime = aged.auth_time;
  expect(invoke('command', aged, { command: 'update_policy' }).res.status).toHaveBeenCalledWith(428);
});
