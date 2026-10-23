'use strict';
const path=require('node:path');
const {runPostgresTests}=require('../../../../scripts/lib/run-postgres-tests');
runPostgresTests({files:['credentials.postgres.cjs','employeeInvitations.postgres.cjs','employeeInvitationHttp.postgres.cjs'].map(file=>path.join(__dirname,'../src/__tests__',file)),environmentVariable:'AUTH_TEST_DATABASE_URL',label:'a9'})
 .catch(error=>{console.error(error.message);process.exitCode=1;});
