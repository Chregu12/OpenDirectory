'use strict';

jest.mock('../config/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn() }));
const fs = require('node:fs'); const path = require('node:path');
const routing = require('../middleware/routing'); const { gatewayAccess, getGatewayPermissions } = require('../middleware/gatewayAccess');
test.each(['GET', 'POST', 'PUT'])('delegates canonical own-company %s without minting global Gateway authority', method => {
  const user = { roles: [], permissions: [] }; const next = jest.fn(); const response = { status: jest.fn().mockReturnThis(), json: jest.fn() };
  gatewayAccess(() => ({ name: 'company-blueprints' }))({ method, path: '/api/company-blueprints', user }, response, next);
  expect(next).toHaveBeenCalledTimes(1); expect(response.status).not.toHaveBeenCalled(); expect(getGatewayPermissions(user)).toEqual([]);
  expect(routing.getServiceRoutes('policy-service')).toContainEqual(expect.objectContaining({ path: '/api/company-blueprints', port: 3004 }));
});
test.each(['/api/company-blueprints-forged', '/api/company-blueprint', '/api/gateway/company-blueprints'])('does not admit near-match %s via the delegated receiver boundary', pathname => {
  const next = jest.fn(); const response = { status: jest.fn().mockReturnThis(), json: jest.fn() };
  gatewayAccess(() => null)({ method: 'POST', path: pathname, user: { roles: [] } }, response, next);
  expect(next).not.toHaveBeenCalled(); expect(response.status).toHaveBeenCalledWith(pathname.startsWith('/api/gateway/') ? 404 : 403);
});
test('the own-company receiver mounts behind verified OIDC but before the unrelated global Policy guard', () => {
  const source = fs.readFileSync(path.resolve(__dirname, '../../../policy-service/src/index.js'), 'utf8');
  const identity = source.indexOf('app.use(oidcAuth('); const company = source.indexOf("app.use('/api/company-blueprints',"); const legacy = source.indexOf("app.use('/api', requirePolicyAccess)");
  expect(identity).toBeGreaterThan(-1); expect(company).toBeGreaterThan(identity); expect(legacy).toBeGreaterThan(company);
  const access = fs.readFileSync(path.resolve(__dirname, '../../../policy-service/src/middleware/policyAccess.js'), 'utf8');
  expect(access).not.toContain('company-blueprints');
});
