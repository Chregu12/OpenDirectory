'use strict';

const path = require('path');
const companyAutomationTest = path.join(__dirname, '../src/__tests__/companyAutomation.postgres.cjs');
const companyGroupRulesTest = path.join(__dirname, '../src/__tests__/companyGroupRules.postgres.cjs');
const accessCleanupTest = path.join(__dirname, '../src/__tests__/companyOffboardingAccess.postgres.cjs');
const { runPostgresTests } = require('../../../../scripts/lib/run-postgres-tests');

runPostgresTests({
  files: ['--test-concurrency=2',path.join(__dirname, '../src/__tests__/postgres.integration.cjs'),path.join(__dirname,'../src/__tests__/tenants.postgres.cjs'),path.join(__dirname,'../src/__tests__/creations.postgres.cjs'),path.join(__dirname,'../src/__tests__/mutations.postgres.cjs'),path.join(__dirname,'../src/__tests__/groupMutations.postgres.cjs'),path.join(__dirname,'../src/__tests__/ouMutations.postgres.cjs'),path.join(__dirname,'../src/__tests__/ouMemberships.postgres.cjs'),path.join(__dirname,'../src/__tests__/groupReviews.postgres.cjs'),path.join(__dirname,'../src/__tests__/authorityCandidates.postgres.cjs'),path.join(__dirname,'../src/__tests__/authorityTenants.postgres.cjs'),path.join(__dirname,'../src/__tests__/ownedPolicies.postgres.cjs'),path.join(__dirname,'../src/__tests__/authorityCheckpoints.postgres.cjs'),path.join(__dirname,'../src/__tests__/organization.postgres.cjs'),path.join(__dirname,'../src/__tests__/companyRegistrations.postgres.cjs'),path.join(__dirname,'../src/__tests__/snapshotBoundary.postgres.cjs'),path.join(__dirname,'../src/__tests__/licenseUserSources.postgres.cjs'),path.join(__dirname,'../src/__tests__/sourceConsentTenant.postgres.cjs'),path.join(__dirname,'../src/__tests__/companyOffboarding.postgres.cjs'),path.join(__dirname,'../src/__tests__/CompanyOffboardingGroups.postgres.cjs'),accessCleanupTest,companyAutomationTest,companyGroupRulesTest],
  environmentVariable: 'IDENTITY_TEST_DATABASE_URL', label: 'identity',
}).catch(error => { console.error(error.message); process.exitCode = 1; });
