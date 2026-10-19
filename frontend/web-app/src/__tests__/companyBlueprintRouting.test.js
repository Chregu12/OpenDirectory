'use strict';

const configuration = require('../../next.config.js');
const { getPathMatch } = require('next/dist/shared/lib/router/utils/path-match');
const blueprintId = '11111111-1111-4111-8111-111111111111';
test.each([
  '/api/company-blueprints', '/api/company-blueprints/capabilities', `/api/company-blueprints/${blueprintId}`,
  `/api/company-blueprints/${blueprintId}/publish`, `/api/company-blueprints/${blueprintId}/restore`,
  `/api/company-blueprints/${blueprintId}/versions`, `/api/company-blueprints/${blueprintId}/versions/1`, `/api/company-blueprints/${blueprintId}/history`,
])('the actual Next first-match router sends %s to the own-company receiver', async pathname => {
  const rules = await configuration.rewrites(); const match = rules.find(rule => getPathMatch(rule.source)(pathname));
  expect(match).toBeDefined();
  expect(match.source).toBe(pathname === '/api/company-blueprints' ? '/api/company-blueprints' : '/api/company-blueprints/:path*');
  expect(match.destination).toBe(`${process.env.POLICY_SERVICE_URL || 'http://policy-service:3004'}${match.source}`);
  expect(rules.indexOf(match)).toBeLessThan(rules.findIndex(rule => rule.source === '/api/:path*'));
});
test('a similarly named path is not admitted as an own-company Blueprint resource', async () => {
  const rules = await configuration.rewrites(); const match = rules.find(rule => getPathMatch(rule.source)('/api/company-blueprints-forged/capabilities'));
  expect(match.source).toBe('/api/:path*');
});
