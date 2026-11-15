'use strict';

const path = require('node:path');
const { runPostgresTests } = require('../../../../scripts/lib/run-postgres-tests');

process.env.TMPDIR = '/tmp';

runPostgresTests({
  files: ['--test-concurrency=1', ...['inventory', 'deviceReturns', 'deviceAgents'].map(name => path.join(__dirname, '../src/__tests__/' + name + '.postgres.cjs'))],
  environmentVariable: 'DEVICE_TEST_DATABASE_URL',
  label: 'device-inventory',
}).catch(error => { console.error(error.message); process.exitCode = 1; });
