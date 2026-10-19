const { randomUUID } = require('node:crypto');
const { normalizePublic, normalizeInternal, validReceipt, validCapabilities } = require('../../../../../packages/company-registration-contract');
const registrationId = randomUUID(); const credentials = { registrationId, username: 'verified', password: 'fixture-password', mfaCode: '', confirm: true };
const receipt = { schemaVersion: 3, registrationId, tenantId: randomUUID(), administratorId: randomUUID(), createdAt: '2026-10-19T00:00:00Z', reviewedAt: '2026-10-19T01:00:00Z', activatedAt: '2026-10-19T02:00:00Z',
  status: 'active', tenantEnabled: true, administratorEnabled: true, profileSaved: true, activationSupported: true, replayed: false, consoleClientId: 'web-app', mfaRequired: true };
test('own activation is explicitly confirmed and the console is only a trusted internal issuer choice', () => {
  expect(normalizePublic('activate', credentials)).toEqual(credentials); expect(normalizeInternal('activate', { registrationId, subject: 'verified', consoleClientId: 'web-app' }).consoleClientId).toBe('web-app');
  for (const body of [{ ...credentials, confirm: false }, { ...credentials, consoleClientId: 'foreign-console' }, { ...credentials, tenantId: randomUUID() }]) expect(() => normalizePublic('activate', body)).toThrow();
});
test('active receipts require actual saved profile, MFA, exact identity and consistent suspension state without access tokens', () => {
  expect(validReceipt(receipt, registrationId)).toBe(true); expect(validReceipt({ ...receipt, status: 'suspended', tenantEnabled: false }, registrationId)).toBe(true);
  for (const changed of [{ ...receipt, mfaRequired: false }, { ...receipt, profileSaved: false }, { ...receipt, status: 'pending-activation' }, { ...receipt, tenantEnabled: false }, { ...receipt, access_token: 'invalid' }, { ...receipt, activatedAt: '2026-10-18T00:00:00Z' }]) expect(validReceipt(changed, registrationId)).toBe(false);
});
test('activation support is versioned and old metadata may never silently advertise activation', () => {
  const capabilities = { schemaVersion: 2, enabled: true, requiresExistingAccount: true, activationSupported: true, status: 'pending-verification' };
  expect(validCapabilities(capabilities)).toBe(true); expect(validCapabilities({ ...capabilities, schemaVersion: 1 })).toBe(false); expect(validCapabilities({ ...capabilities, schemaVersion: 1, activationSupported: false })).toBe(true);
});
