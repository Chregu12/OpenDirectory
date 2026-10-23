'use strict';

const path = require('path');
const { runPostgresTests } = require('../../../../scripts/lib/run-postgres-tests');

runPostgresTests({ files: [path.join(__dirname, '../src/__tests__/clients.postgres.cjs'),path.join(__dirname,'../src/__tests__/companyApps.postgres.cjs'), path.join(__dirname, '../src/__tests__/mfa.postgres.cjs'), path.join(__dirname, '../src/__tests__/revocations.postgres.cjs'), path.join(__dirname, '../src/__tests__/policyDeviceQueue.postgres.cjs')],
  environmentVariable: 'OAUTH_TEST_DATABASE_URL', label: 'oauth' }).catch(error => { console.error(error.message); process.exitCode = 1; });
