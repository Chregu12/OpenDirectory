'use strict';

const configuration = require('../../next.config.js');
const { getPathMatch } = require('next/dist/shared/lib/router/utils/path-match');
const requestId = '11111111-1111-4111-8111-111111111111';
const userId = '22222222-2222-4222-8222-222222222222';
test.each([
  '/api/devices/returns', '/api/devices/returns/capabilities', `/api/devices/returns/${requestId}`,
  `/api/devices/returns/${requestId}/history`, `/api/devices/returns/${requestId}/decision`,
  `/api/devices/users/${userId}/offboarding-returns`, `/api/devices/users/${userId}/offboarding-returns/capabilities`,
  `/api/devices/users/${userId}/offboarding-returns/history`,
])('the actual Next first-match router sends %s to the real device receiver', async pathname => {
  const rules = await configuration.rewrites();
  const match = rules.find(rule => getPathMatch(rule.source)(pathname));
  expect(match).toBeDefined();
  expect(match.destination).toBe(`${process.env.DEVICE_SERVICE_URL || 'http://device-service:3003'}${match.source}`);
  expect(match.source).toBe(pathname.includes('/offboarding-returns') ? '/api/devices/users/:userId/offboarding-returns/:path*' : '/api/devices/returns/:path*');
  expect(rules.indexOf(match)).toBeLessThan(rules.findIndex(rule => rule.source === '/api/:path*'));
});
test('the return routing fix does not route unrelated remote commands into a return handler', async () => {
  const pathname = `/api/devices/${requestId}/lock`; const rules = await configuration.rewrites();
  const match = rules.find(rule => getPathMatch(rule.source)(pathname));
  expect(match.source).toBe('/api/:path*');
});
