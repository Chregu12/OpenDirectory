'use strict';

const path = require('path');
const { runPostgresTests } = require('../../../../scripts/lib/run-postgres-tests');

const tests = path.join(__dirname, '../src/__tests__');
const registration = '^production gateway does not treat a real credential-bound pending company registration';
const blueprints = '^production gateway (registers an actual roleless company blueprint Owner|applies actual roleless company blueprint license origins)';
const assurance = '^company license assurance';
const duties = '^(PIM task groups|Engineering PIM|person group and role|own custom directory roles|custom company device PIM)';

async function main() {
  // Company lifecycle cases deliberately change role/MFA policy; later duties need fresh authority.
  const filters = [`^(?!${registration}|${blueprints}|${assurance}|${duties})[A-Za-z]`, registration, blueprints, assurance, duties];
  for (let index = 0; index < filters.length; index++) {
    const companions = index === 0 ? ['companyLicenseActivations', 'clients', 'companyApps', 'mfa', 'policyDeviceQueue'] : [];
    await runPostgresTests({ files: ['--require=' + path.resolve(__dirname, '../../../../scripts/lib/offboarding-request-diagnostic.cjs'), `--test-name-pattern=${filters[index]}`, ...companions.map(name => path.join(tests, name + '.postgres.cjs')), path.join(tests, 'revocations.postgres.cjs')],
      environmentVariable: 'OAUTH_TEST_DATABASE_URL', label: 'oauth' });
    if (process.exitCode) return;
  }
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
