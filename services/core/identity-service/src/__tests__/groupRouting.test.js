'use strict';

jest.mock('../../../api-gateway/src/config/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn() }));
const routes = require('../../../api-gateway/src/middleware/routing');

test('the gateway resolves group snapshots to identity-service rather than legacy license storage', () => {
  expect(routes.getServiceRoutes('identity-service')).toEqual(expect.arrayContaining([
    expect.objectContaining({ path: '/api/license-groups', port: 3001, service: 'identity-service' }),
    expect.objectContaining({ path: '/api/license-users', port: 3001, service: 'identity-service' }),
  ]));
});

test('license governance and its legacy adapter have distinct services and ports', () => {
  expect(routes.getServiceRoutes('policy-service')).toContainEqual(expect.objectContaining({ path: '/api/licenses', port: 3004 }));
  expect(routes.getServiceRoutes('license-management')).toContainEqual(expect.objectContaining({ path: '/api/license', port: 3018 }));
  const registry = routes.getAllRoutes();
  for (const path of ['/api/license-groups', '/api/license-users']) expect(registry.find(route => route.path === path).service).toBe('identity-service');
});
