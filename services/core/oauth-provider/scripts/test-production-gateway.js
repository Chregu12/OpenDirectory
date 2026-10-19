'use strict';

const path = require('path');
const { runPostgresTests } = require('../../../../scripts/lib/run-postgres-tests');

runPostgresTests({ files: ['--test-name-pattern=^production gateway ', path.join(__dirname, '../src/__tests__/revocations.postgres.cjs')],
  environmentVariable: 'OAUTH_TEST_DATABASE_URL', label: 'prodgw' }).catch(error => { console.error(error.message); process.exitCode = 1; });
