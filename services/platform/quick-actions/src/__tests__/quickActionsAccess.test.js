'use strict';

const { accessClaims } = require('./fixtures/claims');
jest.mock('../../../../../packages/oidc-access-state', () => ({ createAccessStateClient: jest.fn(() => jest.fn(async () => {})) }));
jest.mock('../middleware/verifyApiToken', () => ({ verifyToken: jest.fn() }));
jest.mock('../orchestrators/servicePrincipalOrchestrator');
jest.mock('../orchestrators/deviceEnrollmentOrchestrator');
jest.mock('../orchestrators/userOnboardingOrchestrator');
jest.mock('../orchestrators/policyOrchestrator');
jest.mock('../utils/serviceClient', () => ({ SERVICES: { auth: 'http://auth' }, ping: jest.fn().mockResolvedValue({ healthy: true }) }));

const request = require('supertest');
const app = require('../index');
const { verifyToken } = require('../middleware/verifyApiToken');
const { getQuickActionPermissions, requireQuickActionAccess } = require('../middleware/quickActionsAccess');
const principals = require('../orchestrators/servicePrincipalOrchestrator');
const devices = require('../orchestrators/deviceEnrollmentOrchestrator');
const users = require('../orchestrators/userOnboardingOrchestrator');
const policies = require('../orchestrators/policyOrchestrator');
const { ping } = require('../utils/serviceClient');

function setClaims(value) { verifyToken.mockResolvedValue(accessClaims(value)); }

const routes = [
  ['post', '/service-principals', 'applications.create', principals.createServicePrincipal, {}],
  ['get', '/service-principals', 'applications.read', principals.listServicePrincipals, undefined],
  ['get', '/service-principals/app-id', 'applications.read', principals.getServicePrincipalDetails, undefined],
  ['delete', '/service-principals/app-id', 'applications.delete', principals.deleteServicePrincipal, undefined],
  ['post', '/service-principals/app-id/rotate-secret', 'applications.credentials.rotate', principals.rotateServicePrincipalSecret, {}],
  ['post', '/devices/enroll', 'devices.enroll', devices.enrollDevice, {}],
  ['post', '/devices/bulk-enroll', 'devices.enroll', devices.bulkEnroll, { devices: [{}] }],
  ['get', '/devices/device-id/enrollment-status', 'devices.enrollment.read', devices.getEnrollmentStatus, undefined],
  ['post', '/devices/device-id/unenroll', 'devices.unenroll', devices.unenrollDevice, {}],
  ['post', '/users/onboard', 'users.onboard', users.onboardUser, {}],
  ['post', '/users/user-id/offboard', 'users.offboard', users.offboardUser, {}],
  ['post', '/policies/deploy', 'policies.deploy', policies.deployPolicy, {}],
  ['get', '/policies/deployments/deployment-id', 'policies.deployments.read', policies.getPolicyDeploymentStatus, undefined],
  ['post', '/policies/deployments/deployment-id/rollback', 'policies.rollback', policies.rollbackPolicy, {}],
  ['get', '/compliance/snapshot', 'compliance.read', policies.getComplianceSnapshot, undefined],
  ['get', '/status', 'system.status.read', ping, undefined],
];

beforeEach(() => {
  jest.clearAllMocks();
  setClaims({ sub: 'operator', permissions: [] });
  for (const orchestrator of [principals, devices, users, policies]) {
    for (const handler of Object.values(orchestrator)) handler.mockResolvedValue({ success: true });
  }
  delete process.env.SERVICE_TOKEN;
  delete process.env.QUICK_ACTIONS_ONBOARDING_DEPARTMENTS;
});

function invoke(method, path, body, token = 'header.payload.signature') {
  const operation = request(app)[method](`/api/quick${path}`).set('Authorization', `Bearer ${token}`);
  return body === undefined ? operation : operation.send(body);
}

test.each(routes)('denies an ordinary identity before %s %s can execute', async (method, path, permission, handler, body) => {
  const response = await invoke(method, path, body);
  expect(response.status).toBe(403);
  expect(response.body.permission).toBe(permission);
  expect(handler).not.toHaveBeenCalled();
});

test.each(routes)('allows only the exact operation grant on %s %s', async (method, path, permission, handler, body) => {
  setClaims({ sub: 'operator', permissions: [permission] });
  const response = await invoke(method, path, body);
  expect(response.status).toBeGreaterThanOrEqual(200);
  expect(response.status).toBeLessThan(300);
  expect(handler).toHaveBeenCalledTimes(1);
});

test.each(routes)('scope text cannot authorize %s %s', async (method, path, permission, handler, body) => {
  setClaims({ sub: 'operator', scope: permission, scopes: [permission] });
  const response = await invoke(method, path, body);
  expect(response.status).toBe(403);
  expect(handler).not.toHaveBeenCalled();
});

test.each([{}, { sub: '' }, { sub: ' ' }, { sub: 10 }])('requires a stable actor for every operation: %j', identity => {
  setClaims({ sub: undefined, ...identity, roles: ['admin'] });
  return invoke('get', '/access').then(response => expect(response.status).toBe(401));
});

test('returns only effective server-derived capabilities and prevents caching', async () => {
  setClaims({ sub: 'operator', roles: ['application-reader'], permissions: ['users.offboard', '*', 'unknown'] });
  const response = await invoke('get', '/access');
  expect(response.body).toEqual({ subject: 'operator', permissions: ['applications.read', 'users.offboard'], onboardingDepartments: ['General'], delegablePermissions: ['applications.read', 'users.offboard', 'unknown'] });
  expect(response.headers['cache-control']).toBe('no-store');
});

test('a legacy service credential does not inherit any administrative permissions', async () => {
  process.env.SERVICE_TOKEN = 'legacy-secret';
  const response = await invoke('post', '/users/onboard', { role: 'admin' }, 'svc-legacy-secret');
  expect(response.status).toBe(401);
  expect(verifyToken).not.toHaveBeenCalled();
  expect(users.onboardUser).not.toHaveBeenCalled();
});

test('rejects ID tokens even when they contain an administrator role', async () => {
  setClaims({ sub: 'operator', roles: ['admin'], token_use: 'id' });
  expect((await invoke('get', '/access')).status).toBe(401);
});

test('a new unregistered action cannot reach its handler even for an administrator', () => {
  const next = jest.fn();
  const response = { status: jest.fn().mockReturnThis(), json: jest.fn() };
  requireQuickActionAccess({ method: 'POST', path: '/unreviewed-action', user: { sub: 'operator', roles: ['admin'] } }, response, next);
  expect(response.status).toHaveBeenCalledWith(404);
  expect(next).not.toHaveBeenCalled();
});

test('binds principal creation attribution to the verified subject', async () => {
  setClaims({ sub: 'operator', permissions: ['applications.create'] });
  await invoke('post', '/service-principals', { appName: 'application', createdBy: 'forged-admin' });
  expect(principals.createServicePrincipal).toHaveBeenCalledWith({ appName: 'application', createdBy: 'operator' });
});

test('application creation alone cannot assign application permissions', async () => {
  setClaims({ sub: 'operator', permissions: ['applications.create'] });
  const response = await invoke('post', '/service-principals', { permissions: ['users.offboard'] });
  expect(response.status).toBe(403);
  expect(response.body.permission).toBe('applications.permissions.assign');
  expect(principals.createServicePrincipal).not.toHaveBeenCalled();
});

test('a delegated grant administrator cannot confer permissions they do not hold', async () => {
  setClaims({ sub: 'operator', permissions: ['applications.create', 'applications.permissions.assign', 'directory.read'] });
  expect((await invoke('post', '/service-principals', { permissions: ['directory.write'] })).status).toBe(403);
  expect(principals.createServicePrincipal).not.toHaveBeenCalled();
  expect((await invoke('post', '/service-principals', { permissions: ['directory.read'] })).status).toBe(201);
});

test.each([null, '*', ['*'], ['users.*'], [null], { users: 'admin' }])('rejects malformed or wildcard application grants: %j', permissions => {
  setClaims({ sub: 'operator', roles: ['admin'] });
  return invoke('post', '/service-principals', { permissions }).then(response => {
    expect(response.status).toBe(400);
    expect(principals.createServicePrincipal).not.toHaveBeenCalled();
  });
});

test('unenrollment does not implicitly authorize a destructive wipe', async () => {
  setClaims({ sub: 'operator', permissions: ['devices.unenroll'] });
  expect((await invoke('post', '/devices/device-id/unenroll', { wipe: true })).status).toBe(403);
  expect((await invoke('post', '/devices/device-id/unenroll', { wipe: 'false' })).status).toBe(400);
  expect(devices.unenrollDevice).not.toHaveBeenCalled();
  setClaims({ sub: 'operator', permissions: ['devices.unenroll', 'devices.wipe'] });
  expect((await invoke('post', '/devices/device-id/unenroll', { wipe: true })).status).toBe(200);
});

test.each(['admin', 'elevated'])('onboarding cannot assign a privileged %s role without a separate grant', async role => {
  setClaims({ sub: 'operator', permissions: ['users.onboard'] });
  expect((await invoke('post', '/users/onboard', { role })).status).toBe(403);
  expect(users.onboardUser).not.toHaveBeenCalled();
  setClaims({ sub: 'operator', permissions: ['users.onboard', 'users.roles.assign'] });
  expect((await invoke('post', '/users/onboard', { role })).status).toBe(201);
});

test('onboarding is constrained to approved departments unless group assignment is authorized', async () => {
  setClaims({ sub: 'operator', permissions: ['users.onboard'] });
  expect((await invoke('post', '/users/onboard', { department: 'Administrators' })).status).toBe(403);
  expect(users.onboardUser).not.toHaveBeenCalled();
  process.env.QUICK_ACTIONS_ONBOARDING_DEPARTMENTS = 'General,Engineering';
  expect((await invoke('post', '/users/onboard', { department: 'Engineering' })).status).toBe(201);
  expect((await invoke('post', '/users/onboard', { department: 'General,OU=Admins' })).status).toBe(400);
});

test('onboarding with a device assignment requires separate device assignment authority', async () => {
  setClaims({ sub: 'operator', permissions: ['users.onboard'] });
  expect((await invoke('post', '/users/onboard', { assignDeviceId: 'device-id' })).status).toBe(403);
  expect(users.onboardUser).not.toHaveBeenCalled();
});

test.each([null, {}, { roles: 'admin' }, { roles: ['constructor'] }, { roles: [{ name: 'admin' }] }, { permissions: '*' }, { permissions: ['*'] }])('does not infer grants from malformed authorization claims: %j', user => {
  expect(getQuickActionPermissions(user)).toEqual([]);
});

test('delegated roles stay separated and support trusted realm roles', () => {
  expect(getQuickActionPermissions({ realm_access: { roles: ['application-administrator'] } })).toEqual([
    'applications.read', 'applications.create', 'applications.delete', 'applications.credentials.rotate',
  ]);
  expect(getQuickActionPermissions({ roles: ['user-lifecycle-operator'] })).toEqual(['users.onboard', 'users.offboard']);
  expect(getQuickActionPermissions({ roles: ['device-enrollment-operator'] })).not.toContain('devices.wipe');
});
