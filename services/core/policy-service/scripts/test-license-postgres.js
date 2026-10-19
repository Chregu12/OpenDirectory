'use strict';

const path = require('path');
const { runPostgresTests } = require('../../../../scripts/lib/run-postgres-tests');

runPostgresTests({
  files: ['--test-concurrency=2', ...[
    '../src/licenses/__tests__/postgres.integration.cjs',
    '../src/licenses/__tests__/groups.integration.cjs',
    '../src/licenses/__tests__/fulfillment.integration.cjs',
    '../src/licenses/__tests__/capacity.integration.cjs',
    '../src/licenses/__tests__/reviews.integration.cjs',
    '../src/licenses/__tests__/delegations.integration.cjs',
    '../src/__tests__/policyConfiguration.postgres.cjs',
    '../src/__tests__/policyPublication.postgres.cjs',
    '../src/__tests__/blueprintPreview.postgres.cjs',
    '../src/__tests__/companyBlueprints.postgres.cjs',
    '../src/licenses/__tests__/companyBlueprintAssignments.integration.cjs',
    '../src/licenses/__tests__/companyBlueprintLifecycle.integration.cjs',
    '../src/licenses/__tests__/companyLicenses.integration.cjs',
    '../src/licenses/__tests__/companyOffboardingJournal.unit.cjs',
    '../src/licenses/__tests__/companyOffboardingJournal.integration.cjs',
  ].map(filename => path.join(__dirname, filename))],
  environmentVariable: 'LICENSE_TEST_DATABASE_URL', label: 'license',
}).catch(error => { console.error(error.message); process.exitCode = 1; });
