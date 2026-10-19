'use strict';

const path = require('node:path');
const { runPostgresTests } = require('../../../../scripts/lib/run-postgres-tests');

runPostgresTests({
  files: [path.join(__dirname, '../src/licenses/__tests__/companyLicenses.integration.cjs')],
  environmentVariable: 'LICENSE_TEST_DATABASE_URL',
  label: 'company-licenses',
}).catch(error => { console.error(error.message); process.exitCode = 1; });
