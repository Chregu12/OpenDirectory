import fs from 'node:fs';
import path from 'node:path';
const root = path.resolve(__dirname, '../../../..');
test('the frontend image includes the actual shared role catalog used by access cleanup', () => {
  const dockerfile = fs.readFileSync(path.join(root, 'frontend/web-app/Dockerfile'), 'utf8');
  expect(dockerfile).toContain('COPY packages/directory-role-contract.js /packages/directory-role-contract.js');
  expect(fs.existsSync(path.join(root, 'packages/directory-role-contract.js'))).toBe(true);
});
test.each(['docker-compose.yml', 'docker-compose.lite.yml'])('%s builds the frontend from the root so its shared profile contract exists', filename => {
  const compose = fs.readFileSync(path.join(root, filename), 'utf8');
  expect(compose).toMatch(/web-app:\s+build:\s+context: \.\s+dockerfile: frontend\/web-app\/Dockerfile/);
});
test.each(['frontend/web-app/Dockerfile', 'services/core/identity-service/Dockerfile'])('%s includes the same shared organization contract', filename => {
  const dockerfile = fs.readFileSync(path.join(root, filename), 'utf8');
  expect(dockerfile).toContain('COPY packages/organization-profile-contract/ /packages/organization-profile-contract/');
  expect(fs.existsSync(path.join(root, 'packages/organization-profile-contract/index.js'))).toBe(true);
});
test.each(['docker-compose.yml', 'docker-compose.lite.yml'])('company registration remains explicitly disabled by default in %s', file => {
  const fs = require('node:fs'); const path = require('node:path'); const source = fs.readFileSync(path.resolve(__dirname, '../../../..', file), 'utf8');
  expect(source).toContain('COMPANY_REGISTRATION_ENABLED=${COMPANY_REGISTRATION_ENABLED:-false}');
});
test.each(['frontend/web-app/Dockerfile', 'services/core/identity-service/Dockerfile', 'services/core/oauth-provider/Dockerfile'])('%s includes the real shared registration and profile contracts', file => {
  const fs = require('node:fs'); const path = require('node:path'); const source = fs.readFileSync(path.resolve(__dirname, '../../../..', file), 'utf8');
  expect(source).toContain('COPY packages/company-registration-contract/ /packages/company-registration-contract/');
  expect(source).toContain('COPY packages/organization-profile-contract/ /packages/organization-profile-contract/');
});
