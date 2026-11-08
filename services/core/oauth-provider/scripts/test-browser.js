'use strict';

const path = require('path');
const { runPostgresTests } = require('../../../../scripts/lib/run-postgres-tests');

const browserTests = path.join(__dirname, '../src/__tests__/browser.postgres.cjs');
const company = '^real company registration UI persists';
const owner = '^(real own-company|real organization profile|real browser MFA enrollment|real recurring review)';
const automation = '^(real company automation|real change-driven|real roleless Owner)';

// Each group starts fresh services and a disposable schema. The complete suite
// otherwise exceeds the real per-IP 15-minute service limits from one browser.
async function main() {
  for (const filter of [`--test-skip-pattern=${company}|${owner}|${automation}`, `--test-name-pattern=${company}`, `--test-name-pattern=${owner}`, `--test-name-pattern=${automation}`]) {
    await runPostgresTests({ files: [filter, browserTests], environmentVariable: 'OAUTH_TEST_DATABASE_URL', label: 'browser' });
    if (process.exitCode) return;
  }
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
