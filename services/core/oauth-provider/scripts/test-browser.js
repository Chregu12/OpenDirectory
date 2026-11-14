'use strict';

const path = require('path');
const { runPostgresTests } = require('../../../../scripts/lib/run-postgres-tests');

const browserTests = path.join(__dirname, '../src/__tests__/browser.postgres.cjs');
const company = '^real company registration UI persists';
const ownerBlueprint = '^real own-company blueprint Owner';
const ownerProfile = '^(real organization profile|real browser MFA enrollment|real recurring review)';
const ownerAssignments = '^real own-company Owner';
const automation = '^(real company automation|real change-driven|real roleless Owner)';
const governance = '^(the actual |real (provider |license |membership |administrative |mandatory pool |pool PIM |scoped licensing))';
const employee = '^real employee invitation';

// Each group starts fresh services and a disposable schema. The complete suite
// otherwise exceeds the real per-IP 15-minute service limits from one browser.
async function main() {
  // A positive prefix excludes Node 20's <root>, whose match would include every child.
  for (const filter of [`--test-name-pattern=^(?!${company}|${ownerBlueprint}|${ownerProfile}|${ownerAssignments}|${automation}|${governance}|${employee})[a-z]`, `--test-name-pattern=${governance}`, `--test-name-pattern=${company}`, `--test-name-pattern=${ownerBlueprint}`, `--test-name-pattern=${ownerProfile}`, `--test-name-pattern=${ownerAssignments}`, `--test-name-pattern=${automation}`, `--test-name-pattern=${employee}`]) {
    await runPostgresTests({ files: [filter, browserTests], environmentVariable: 'OAUTH_TEST_DATABASE_URL', label: 'browser' });
    if (process.exitCode) return;
  }
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
