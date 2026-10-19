'use strict';

const configuration = require('../../next.config.js');
const { getPathMatch } = require('next/dist/shared/lib/router/utils/path-match');
const base = '/api/company-blueprint-assignments';
const assignmentId = '11111111-1111-4111-8111-111111111111';

test.each([base, `${base}/`, `${base}/${assignmentId}`, `${base}/${assignmentId}/remove`])(
  'the actual Next first-match router sends %s to the Policy receiver', async pathname => {
    const rules = await configuration.rewrites();
    const match = rules.find(rule => getPathMatch(rule.source)(pathname));
    expect(match).toBeDefined();
    expect(match.source).toBe(pathname === base || pathname === `${base}/` ? base : `${base}/:path*`);
    expect(match.destination).toBe(`${process.env.POLICY_SERVICE_URL || 'http://policy-service:3004'}${match.source}`);
    expect(rules.indexOf(match)).toBeLessThan(rules.findIndex(rule => rule.source === '/api/:path*'));
  },
);

test('the installed Next wildcard matches the namespace root as well as nested paths', async () => {
  const rules = await configuration.rewrites();
  const wildcard = rules.find(rule => rule.source === `${base}/:path*`);
  expect(wildcard).toBeDefined();
  const match = getPathMatch(wildcard.source);
  expect(match(base)).not.toBe(false);
  expect(match(`${base}/${assignmentId}`)).toEqual({ path: [assignmentId] });
});

test.each([
  `${base}-forged`, `${base}forged`, '/api/company-blueprint-assignment',
  `${base}%2Fforged`, `${base}-forged/${assignmentId}`,
])('the actual Next matcher does not admit near-match %s into the assignment namespace', async pathname => {
  const rules = await configuration.rewrites();
  const match = rules.find(rule => getPathMatch(rule.source)(pathname));
  expect(match.source).toBe('/api/:path*');
  for (const rule of rules.filter(rule => rule.source === base || rule.source === `${base}/:path*`)) {
    expect(getPathMatch(rule.source)(pathname)).toBe(false);
  }
});

test('both assignment rewrites preserve the namespace at the configured Policy service', async () => {
  const previous = process.env.POLICY_SERVICE_URL;
  process.env.POLICY_SERVICE_URL = 'http://policy-test:3004';
  try {
    const rules = await configuration.rewrites();
    for (const source of [base, `${base}/:path*`]) {
      expect(rules.filter(rule => rule.source === source)).toEqual([{ source, destination: `http://policy-test:3004${source}` }]);
    }
  } finally {
    if (previous === undefined) delete process.env.POLICY_SERVICE_URL;
    else process.env.POLICY_SERVICE_URL = previous;
  }
});
