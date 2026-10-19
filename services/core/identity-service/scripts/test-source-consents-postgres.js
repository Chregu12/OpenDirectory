'use strict';

const path=require('node:path');
const {runPostgresTests}=require('../../../../scripts/lib/run-postgres-tests');
runPostgresTests({files:[path.join(__dirname,'../src/__tests__/sourceConsentTenant.postgres.cjs')],environmentVariable:'IDENTITY_TEST_DATABASE_URL',label:'source-consent-tenant'})
 .catch(error=>{console.error(error.message);process.exitCode=1;});
