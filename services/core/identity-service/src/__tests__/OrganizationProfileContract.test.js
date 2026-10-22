const { FIELDS, normalizeProfile, organizationEtag } = require('../../../../../packages/organization-profile-contract');
const profile = { name: 'Company AG', legalForm: '', registrationNumber: '', taxId: '', addressLine1: 'Street 1', addressLine2: '', postalCode: '8000', city: 'Zürich', country: 'CH', timezone: 'UTC', defaultLanguage: 'de', contactEmail: 'contact@example.invalid', contactPhone: '', website: '' };
test('normalizes only explicit profile fields without inventing company or verification data', () => {
  expect(normalizeProfile({ ...profile, name: '  Company AG  ' })).toEqual(profile);
  expect(Object.keys(normalizeProfile(profile))).toEqual(Object.keys(FIELDS));
});
test.each([null, [], {}, { ...profile, tenantId: 'foreign' }, { ...profile, contactEmail: 'invalid' }, { ...profile, timezone: 'Invalid/Zone' }, { ...profile, website: 'http://example.invalid' }, { ...profile, website: 'https://user:password@example.invalid' }, { ...profile, name: 'bad\nname' }, { ...profile, defaultLanguage: 'xx' }])('rejects malformed or unsafe organization data %j', value => {
  expect(() => normalizeProfile(value)).toThrow('invalid_organization_profile');
});
test.each(Object.entries(FIELDS))('enforces the exact maximum for %s', (field, maximum) => {
  expect(() => normalizeProfile({ ...profile, [field]: 'x'.repeat(maximum + 1) })).toThrow();
});
test('keeps tenant lifecycle and profile revisions exact above the safe integer range', () => {
  expect(organizationEtag({ id: 'actual', generation: '9007199254740993', version: '9223372036854775806' }, '9223372036854775807')).toBe('"organization-actual-9007199254740993-9223372036854775806-9223372036854775807"');
});
test('the generated OpenAPI schema documents the exact complete field set and conditional receiving boundary', () => {
  const { organizationOpenApi } = require('../../scripts/organization-openapi'); const document = organizationOpenApi();
  expect(document.openapi).toBe('3.1.0'); expect(document.components.schemas.OrganizationValues.required).toEqual(Object.keys(FIELDS));
  for (const [field, maximum] of Object.entries(FIELDS)) expect(document.components.schemas.OrganizationValues.properties[field].maxLength).toBe(maximum);
  expect(document.paths['/api/identity/organization'].put.parameters[0]).toMatchObject({ name: 'If-Match', required: true });
});
test('the checked-in API document is generated from the current shared contract', () => {
  const fs = require('node:fs'); const path = require('node:path'); const { organizationOpenApi } = require('../../scripts/organization-openapi');
  expect(JSON.parse(fs.readFileSync(path.join(__dirname, '../../../../../docs/api/openapi.yaml'), 'utf8'))).toEqual(organizationOpenApi());
});
test('every minimal license or policy source documents the mandatory receiving protocol without a tenant selector', () => {
  const document = require('../../scripts/organization-openapi').organizationOpenApi();
  for (const source of ['license-users', 'license-groups', 'license-reviewers', 'license-scope-reviewers', 'license-activation-reviewers', 'license-delegates', 'policy-publication-actors']) {
    const route = document.paths['/api/' + source + '/{id}/snapshot'];
    expect(Object.keys(route)).toEqual(['get']);
    expect(route.get.parameters.map(parameter => parameter.name)).toEqual(['id']);
    expect(route.get.responses[200].headers['X-OD-License-Snapshot-Protocol'].schema).toEqual({ type: 'string', const: '1' });
    expect(route.get.responses[404]).toBeDefined();
  }
  expect(document.components.schemas.LicenseUserSnapshot.required).toEqual(['schemaVersion', 'userId', 'revision', 'enabled', 'deleted']);
  expect(document.components.schemas.LicenseGroupSnapshot.properties.schemaVersion.const).toBe(3);
});
test('company license operations document real finite inventory, exact versions and explicit original source without a global licensing permission', () => {
  const document = require('../../scripts/organization-openapi').organizationOpenApi(); const schemas = document.components.schemas;
  expect(document.info.version).toBe('1.22.0'); expect(schemas.CompanyLicensePool.properties.totalSeats).toEqual({ type: 'integer', minimum: 1, maximum: 10000 });
  expect(schemas.CompanyLicensePool.properties.allocationMode.const).toBe('local-only'); expect(schemas.CompanyLicenseCapabilities.properties.permissions.const).toEqual(['company.apps.read', 'company.apps.create', 'company.apps.assign']);
  expect(document.paths['/api/licenses/company/pools/{id}/assignments'].post.parameters).toEqual(expect.arrayContaining([expect.objectContaining({ name: 'If-Match', required: true })]));
  expect(document.paths['/api/licenses/company/pools/{id}/assignments/{assignmentId}/revoke'].post.requestBody.content['application/json'].schema.properties.confirm.const).toBe(true);
  expect(document.paths['/api/identity/company-licenses'].post.requestBody.content['application/json'].schema.required).toEqual(['userId']);
  expect(schemas.CompanyLicenseEvent.properties.deliveryStatus.const).toBe('pending');
  expect(schemas.CompanyLicenseEvent.properties.type.enum).toContain('app.license.pool.updated');
  expect(schemas.CompanyPoolEditCapabilities.properties.companyPoolEditProtocol.const).toBe(1);
  const edit = document.paths['/api/licenses/company/pools/{id}'].patch;
  expect(edit.parameters.map(parameter => parameter.name)).toEqual(['id', 'If-Match']);
  expect(edit.requestBody.content['application/json'].schema.required).toEqual(['name', 'vendor', 'description', 'totalSeats', 'reason', 'confirm']);
  expect(edit.requestBody.content['application/json'].schema.properties.confirm.const).toBe(true);
  expect(edit.responses[200].content['application/json'].schema.$ref).toBe('#/components/schemas/CompanyLicensePool');
  const returns = document.paths['/api/licenses/company/users/{userId}/license-returns'];
  expect(returns.post.requestBody.content['application/json'].schema.properties.assignments.maxItems).toBe(25);
  expect(returns.post.responses[207].content['application/json'].schema.$ref).toBe('#/components/schemas/CompanyLicenseReturnResult');
  expect(schemas.CompanyLicenseReturnPreview.properties.limit.maximum).toBe(25);
  expect(schemas.CompanyLicenseReturnResult.properties.results.items.oneOf.map(item => item.properties.status.const)).toEqual(['released', 'unconfirmed', 'not_attempted']);
  expect(schemas.CompanyOffboardingAccountReceipt.required).toHaveLength(13);
  expect(document.paths['/api/users/{userId}/company-offboarding'].post.requestBody.content['application/json'].schema.required).toEqual(['workflowId', 'expectedRevision', 'confirm']);
  expect(document.paths['/api/licenses/company/offboarding-workflows/{id}/continue'].post.requestBody.content['application/json'].schema.properties.assignments.maxItems).toBe(25);
  expect(schemas.CompanyOffboardingCapability.properties.scope.const).toBe('account-and-local-licenses');
});
