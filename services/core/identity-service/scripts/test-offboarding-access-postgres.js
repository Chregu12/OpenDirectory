'use strict';

const path = require('path');
const { runPostgresTests } = require('../../../../scripts/lib/run-postgres-tests');
runPostgresTests({ files: [path.join(__dirname, '../src/__tests__/companyOffboardingAccess.postgres.cjs')], environmentVariable: 'IDENTITY_TEST_DATABASE_URL', label: 'offboarding-access' }).catch(error => { console.error(error); process.exitCode = 1; });
