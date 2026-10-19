'use strict';

const path = require('path');
const { runPostgresTests } = require('../../../../scripts/lib/run-postgres-tests');

runPostgresTests({ files: [path.join(__dirname, '../src/__tests__/browser.postgres.cjs')],
  environmentVariable: 'OAUTH_TEST_DATABASE_URL', label: 'browser' }).catch(error => { console.error(error.message); process.exitCode = 1; });
