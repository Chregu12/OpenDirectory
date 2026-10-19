const { randomUUID } = require('node:crypto');
const { normalizeInternal, normalizePublic, principalFor, validReceipt } = require('../../../../../packages/company-registration-contract');
const { requestDigest } = require('../../../../../packages/company-registration-contract/digest');
const registrationId = randomUUID(); const subject = 'verified-credential'; const principal = { username: 'verified', email: 'verified@example.invalid', displayName: 'Verified Person' };
const profile = { name: 'Company AG', legalForm: '', registrationNumber: '', taxId: '', addressLine1: 'Street 1', addressLine2: '', postalCode: '8000', city: 'Zürich', country: 'CH', timezone: 'UTC', defaultLanguage: 'de', contactEmail: 'office@example.invalid', contactPhone: '', website: '' };
const internal = { registrationId, subject, principal, profile }; const credentials = { registrationId, username: 'verified', password: 'not-stored-provider-password', mfaCode: '' };
test('the canonical request carries only a verified credential principal and draft profile, never password, roles or arbitrary tenant IDs', () => {
  expect(normalizeInternal('submit', internal)).toEqual(internal); expect(normalizePublic('submit', { ...credentials, profile, confirm: true })).toEqual({ ...credentials, profile, confirm: true });
  expect(principalFor({ id: subject, ...principal, roles: ['admin'], permissions: ['*'] })).toEqual({ subject, principal });
});
test.each([null, [], { ...internal, tenantId: randomUUID() }, { ...internal, principal: { ...principal, roles: ['admin'] } }, { ...internal, subject: 'bad\nsubject' },
  { ...internal, principal: { ...principal, email: 'missing-email' } }, { ...internal, profile: { ...profile, website: 'http://unsafe.invalid' } }, { ...internal, registrationId: 'not-canonical' }])('rejects malformed or privilege-bearing private requests %#', value => {
  expect(() => normalizeInternal('submit', value)).toThrow();
});
test.each([{ ...credentials, profile, confirm: false }, { ...credentials, profile, confirm: true, userId: randomUUID() }, { ...credentials, profile, confirm: true, password: '' },
  { ...credentials, profile, confirm: true, mfaCode: 123456 }])('public registration requires the explicit pending-only intent and exact credentials %#', value => { expect(() => normalizePublic('submit', value)).toThrow(); });
test('the digest binds operation, credential subject, registration key and every normalized company field', () => {
  const digest = requestDigest('submit', internal); expect(digest).toMatch(/^[a-f0-9]{64}$/);
  for (const change of [{ ...internal, registrationId: randomUUID() }, { ...internal, subject: 'other-subject' }, { ...internal, profile: { ...profile, city: 'Bern' } }]) expect(requestDigest('submit', change)).not.toBe(digest);
  expect(requestDigest('status', { registrationId, subject })).not.toBe(digest);
});
test('only exact persisted pending receipts are accepted; no activated, privileged, token-bearing or foreign response is a success', () => {
  const receipt = { schemaVersion: 1, registrationId, tenantId: randomUUID(), administratorId: randomUUID(), createdAt: '2026-10-19T00:00:00Z', status: 'pending-verification', tenantEnabled: false, administratorEnabled: false, profileSaved: false, activationSupported: false, replayed: false };
  expect(validReceipt(receipt, registrationId)).toBe(true);
  for (const changed of [{ ...receipt, tenantEnabled: true }, { ...receipt, administratorEnabled: true }, { ...receipt, access_token: 'not-allowed' }, { ...receipt, status: 'active' }, { ...receipt, registrationId: randomUUID() }, { ...receipt, profileSaved: true }]) expect(validReceipt(changed, registrationId)).toBe(false);
});
test('the generated registration contract separates anonymous credentials from the private proof and advertises no activation or access token', () => {
  const document = require('../../scripts/organization-openapi').organizationOpenApi();
  expect(document.paths['/api/company-registration/submit'].post.security).toEqual([]);
  expect(document.paths['/internal/identity/company-registrations/submit'].post.security).toEqual([{ companyRegistrationWorkload: [] }]);
  expect(document.components.schemas.CompanyRegistrationReceipt.properties.tenantEnabled.const).toBe(false);
  expect(document.components.schemas.CompanyRegistrationReceipt.properties.activationSupported.const).toBe(false);
  expect(document.paths['/api/company-registration/submit'].post.responses).not.toHaveProperty('428');
});
