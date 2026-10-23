'use strict';
const path=require('node:path');
const {runPostgresTests}=require('../../../../scripts/lib/run-postgres-tests');
runPostgresTests({files:[path.join(__dirname,'../src/__tests__/credentials.postgres.cjs')],environmentVariable:'AUTH_TEST_DATABASE_URL',label:'a9'})
 .catch(error=>{console.error(error.message);process.exitCode=1;});
