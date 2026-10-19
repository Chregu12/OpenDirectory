'use strict';

jest.mock('../config/logger', () => ({ debug: jest.fn(), info: jest.fn(), warn: jest.fn(), error: jest.fn(), performance: jest.fn() }));
const fs = require('node:fs');
const path = require('node:path');
const routing = require('../middleware/routing');
const { gatewayAccess, getGatewayPermissions } = require('../middleware/gatewayAccess');
const base = '/api/company-blueprint-assignments';
const assignmentId = '11111111-1111-4111-8111-111111111111';

test.each([
  ['GET', base], ['GET', `${base}/`], ['GET', `${base}/${assignmentId}`],
  ['POST', base], ['PUT', `${base}/${assignmentId}`], ['PATCH', `${base}/${assignmentId}`], ['DELETE', `${base}/${assignmentId}`],
])('routes and delegates %s %s to Policy without global Gateway authority', (method, pathname) => {
  const user = { roles: [], permissions: [] };
  const request = { method, path: pathname, user };
  const response = { on: jest.fn(), status: jest.fn().mockReturnThis(), json: jest.fn() };
  const next = jest.fn();
  routing(request, response, next);
  expect(request.targetService).toEqual(expect.objectContaining({ service: 'policy-service', port: 3004 }));
  expect(request.path).toBe(pathname);
  expect(next).toHaveBeenCalledTimes(1);
  next.mockClear();
  gatewayAccess(() => ({ name: 'company-blueprint-assignments' }))(request, response, next);
  expect(next).toHaveBeenCalledTimes(1);
  expect(response.status).not.toHaveBeenCalled();
  expect(request.user).toBe(user);
  expect(request.gatewayPermissions).toEqual([]);
  expect(getGatewayPermissions(user)).toEqual([]);
  expect(routing.getServiceRoutes('policy-service')).toContainEqual(expect.objectContaining({ path: base, port: 3004 }));
});

test.each([
  `${base}-forged`, `${base}forged`, '/api/company-blueprint-assignment',
  `${base}%2Fforged`, `${base}-forged/${assignmentId}`, '/api/gateway/company-blueprint-assignments',
])('does not admit near-match %s through routing or the delegated boundary', pathname => {
  const request = { method: 'POST', path: pathname, user: { roles: [], permissions: [] } };
  const response = { on: jest.fn(), status: jest.fn().mockReturnThis(), json: jest.fn() };
  routing(request, response, jest.fn());
  expect(request.targetService).toBeUndefined();
  const next = jest.fn();
  gatewayAccess(() => ({ name: 'company-blueprint-assignments' }))(request, response, next);
  expect(next).not.toHaveBeenCalled();
  expect(response.status).toHaveBeenCalledWith(pathname.startsWith('/api/gateway/') ? 404 : 403);
});

test('delegating an assignment request does not grant Gateway control-plane access', () => {
  const user = { roles: [], permissions: [] };
  const response = { status: jest.fn().mockReturnThis(), json: jest.fn() };
  const next = jest.fn();
  const access = gatewayAccess(() => ({ name: 'company-blueprint-assignments' }));
  access({ method: 'GET', path: base, user }, response, next);
  expect(next).toHaveBeenCalledTimes(1);
  next.mockClear();
  access({ method: 'GET', path: '/api/gateway/info', user }, response, next);
  expect(next).not.toHaveBeenCalled();
  expect(response.status).toHaveBeenCalledWith(403);
  expect(response.json).toHaveBeenCalledWith({ error: 'forbidden', permission: 'gateway.status.read' });
  expect(getGatewayPermissions(user)).toEqual([]);
});

test('the assignment receiver mounts behind verified OIDC but before the global Policy guard', () => {
  const source = fs.readFileSync(path.resolve(__dirname, '../../../policy-service/src/index.js'), 'utf8');
  const identity = source.indexOf('app.use(oidcAuth(');
  const assignments = source.indexOf("app.use('/api/company-blueprint-assignments',");
  const legacy = source.indexOf("app.use('/api', requirePolicyAccess)");
  expect(identity).toBeGreaterThan(-1);
  expect(assignments).toBeGreaterThan(identity);
  expect(legacy).toBeGreaterThan(assignments);
  expect(source).toContain("require('./companyBlueprintAssignmentRoutes').companyBlueprintAssignmentRoutes(db)");
  const access = fs.readFileSync(path.resolve(__dirname, '../../../policy-service/src/middleware/policyAccess.js'), 'utf8');
  expect(access).not.toContain('company-blueprint-assignments');
});

test('the actual Gateway registers the assignment namespace as a non-rewriting Policy proxy', () => {
  const source = fs.readFileSync(path.resolve(__dirname, '../index.js'), 'utf8');
  const registration = source.match(/if \(enabledModules\.includes\('policy-service'\)\) \{([\s\S]*?)connectedServices\.push\('policy-service'\);/);
  expect(registration).not.toBeNull();
  const names = registration[1].match(/for \(const name of \[([^\]]+)\]\)/);
  expect(names).not.toBeNull();
  expect(names[1].split(',').map(name => name.trim())).toContain("'company-blueprint-assignments'");
  expect(registration[1]).toContain("process.env.POLICY_SERVICE_URL || 'http://policy-service:3004'");
  expect(registration[1]).toContain("const pathPrefix = '/api/' + name;");
  expect(registration[1]).toContain('this.app.use(pathPrefix, createProxyMiddleware({ target: licenseTarget, changeOrigin: true }));');
  expect(registration[1]).toContain('this.services.set(name, { name, target: licenseTarget, pathPrefix,');
  expect(registration[1]).not.toContain('pathRewrite');
});
