'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { reviewSettings, readManifest, confirmCandidate } = require('../../scripts/authority-review');
const { ROLES } = require('../../../../../packages/directory-role-contract');
const tenant = '11111111-1111-4111-8111-111111111111';
const environment = { IDENTITY_AUTHORITY_REVIEW_DATABASE_URL: 'postgres://review:private@127.0.0.1/review', IDENTITY_AUTHORITY_REVIEW_SCHEMA: 'owned_review' };

test('inventory and staging require explicit isolated review credentials and schema, never the application default', () => {
  expect(reviewSettings(['inventory', tenant, 'https://issuer.test'], environment)).toMatchObject({ mode: 'inventory', schema: 'owned_review', first: tenant, issuer: 'https://issuer.test' });
  expect(reviewSettings(['stage', '/tmp/review.json'], environment)).toMatchObject({ mode: 'stage', first: '/tmp/review.json' });
  expect(reviewSettings(['plan', tenant, tenant, 'https://issuer.test'], environment)).toMatchObject({ mode: 'plan', first: tenant, tenantId: tenant, issuer: 'https://issuer.test' });
  expect(() => reviewSettings(['inventory', tenant, 'https://issuer.test'], { DATABASE_URL: environment.IDENTITY_AUTHORITY_REVIEW_DATABASE_URL })).toThrow('Explicit IDENTITY_AUTHORITY_REVIEW_DATABASE_URL');
});
test.each([[], ['activate', tenant], ['stage', '/tmp/review.json', 'https://issuer.test'], ['inventory', tenant], ['inventory', tenant, 'https://issuer.test', 'extra']].map(args => [args]))('unsupported review commands fail before connecting: %j', args => {
  expect(() => reviewSettings(args, environment)).toThrow();
});
test.each([['plan', tenant], ['plan', tenant, tenant], ['plan', 'unknown', tenant, 'https://issuer.test'], ['plan', tenant, 'unknown', 'https://issuer.test'],
  ['plan', tenant, tenant, 'https://issuer.test', 'extra']].map(args => [args]))('source planning requires explicit candidate, owner and issuer: %j', args => {
  expect(() => reviewSettings(args, environment)).toThrow();
});
test.each(['public; SET ROLE admin', '../public', 'public,pg_temp', 'OwnedSchema', ''])('schema identifiers cannot become SQL: %s', schema => {
  expect(() => reviewSettings(['stage', '/tmp/review.json'], { ...environment, IDENTITY_AUTHORITY_REVIEW_SCHEMA: schema })).toThrow();
});
test.each(['https://host/database', 'postgres://host', 'postgres://host/db#fragment'])('the review connection must be a named PostgreSQL database: %s', connection => {
  expect(() => reviewSettings(['stage', '/tmp/review.json'], { ...environment, IDENTITY_AUTHORITY_REVIEW_DATABASE_URL: connection })).toThrow();
});
test.each(['file:///authority', 'https://user:secret@issuer.test', 'https://issuer.test?tenant=other', 'https://issuer.test#other'])('issuer selectors cannot introduce credentials or query ownership: %s', issuer => {
  expect(() => reviewSettings(['inventory', tenant, issuer], environment)).toThrow();
});
test('manifest files are bounded, explicit JSON objects without hidden defaults', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'od-authority-cli-'));
  try {
    const filename = path.join(directory, 'review.json'); fs.writeFileSync(filename, JSON.stringify({ schemaVersion: 1, tenantId: tenant })); expect(readManifest(filename)).toEqual({ schemaVersion: 1, tenantId: tenant });
    for (const data of ['', 'null', '[]', 'not-json']) { fs.writeFileSync(filename, data); expect(() => readManifest(filename)).toThrow(); }
    fs.writeFileSync(filename, Buffer.alloc(2 * 1024 * 1024 + 1)); expect(() => readManifest(filename)).toThrow('at most 2 MiB'); expect(() => readManifest(directory)).toThrow();
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

const candidateManifest = { tenantId: tenant, policies: ROLES.map(role => ({ role })), sources: [{}, {}] };
const candidate = { id: '22222222-2222-4222-8222-222222222222', tenantId: tenant, state: 'draft', canAuthorize: false, validUntil: '2026-10-19T01:00:00.000Z', manifestSha256: 'a'.repeat(64), inventorySha256: 'b'.repeat(64), policyCount: ROLES.length, adoptionIntentCount: 1, quarantineIntentCount: 1 };
test('candidate confirmation describes draft intentions only, not a completed grant or quarantine', () => {
  expect(confirmCandidate(candidate, candidateManifest)).toBe(candidate);
});
test.each([null, {}, { ...candidate, state: 'active' }, { ...candidate, canAuthorize: true }, { ...candidate, tenantId: candidate.id }, { ...candidate, manifestSha256: 'fake' }, { ...candidate, validUntil: 'not-a-date' }, { ...candidate, adoptionIntentCount: 2 }, { ...candidate, extra: true }])('malformed or positive-looking staging responses are never confirmed: %j', response => {
  expect(() => confirmCandidate(response, candidateManifest)).toThrow('did not confirm');
});
