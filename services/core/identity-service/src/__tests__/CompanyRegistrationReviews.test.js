const { randomUUID } = require('node:crypto');
const { normalizeReview, validReceipt } = require('../../../../../packages/company-registration-contract');
const { getIdentityPermissions, requireIdentityAccess } = require('../middleware/identityAccess');
const { argumentsForOperator } = require('../../scripts/company-review-operator');
const id = randomUUID(); const body = { decision: 'approved', reason: 'Independent actual company evidence review', confirm: true };
test('review requires an explicit final decision and bounded reason without tenant selectors or privilege payloads', () => {
  expect(normalizeReview({ ...body, reason: '  Independently reviewed company  ' })).toEqual({ ...body, reason: 'Independently reviewed company' });
  expect(normalizeReview({ ...body, decision: 'rejected' }).decision).toBe('rejected');
});
test.each([null, [], { ...body, decision: 'active' }, { ...body, confirm: false }, { ...body, reason: 'short' }, { ...body, reason: 'Hidden\ncontrol in reason' },
  { ...body, tenantId: id }, { ...body, reason: 'x'.repeat(501) }])('invalid review %# fails before a command', value => { expect(() => normalizeReview(value)).toThrow(); });
test('approved and rejected applicant receipts are versioned, exact and still never represent activation or expose private review evidence', () => {
  const receipt = { schemaVersion: 2, registrationId: id, tenantId: randomUUID(), administratorId: randomUUID(), createdAt: '2026-10-19T00:00:00Z', status: 'pending-activation',
    reviewedAt: '2026-10-19T01:00:00Z', tenantEnabled: false, administratorEnabled: false, profileSaved: false, activationSupported: false, replayed: true };
  expect(validReceipt(receipt, id)).toBe(true); expect(validReceipt({ ...receipt, status: 'rejected' }, id)).toBe(true);
  for (const changed of [{ ...receipt, status: 'active' }, { ...receipt, tenantEnabled: true }, { ...receipt, reason: 'private' }, { ...receipt, reviewedAt: '2026-10-18T00:00:00Z' }, { ...receipt, reviewedAt: undefined }, { ...receipt, schemaVersion: 1 }]) expect(validReceipt(changed, id)).toBe(false);
});
test('global admin and caller-supplied claims do not grant platform review permission; only the closed request-only server capability does', () => {
  expect(getIdentityPermissions({ roles: ['admin'], permissions: ['company.registrations.review'] })).not.toContain('company.registrations.review');
  const req = { user: { sub: 'human', roles: ['admin'], permissions: ['company.registrations.review'] }, method: 'GET', path: '/identity/company-registrations', query: {}, headers: {} };
  const res = { status: jest.fn().mockReturnThis(), json: jest.fn() }; const next = jest.fn(); requireIdentityAccess(req, res, next); expect(res.status).toHaveBeenCalledWith(403); expect(next).not.toHaveBeenCalled();
  req.companyRegistrationPermissions = ['company.registrations.review', 'injected.arbitrary.permission']; requireIdentityAccess(req, res, next); expect(next).toHaveBeenCalledTimes(1); expect(req.identityPermissions).not.toContain('injected.arbitrary.permission');
});
test('offline operator parser requires explicit issuer, canonical person, expected version and reviewed enable/disable', () => {
  expect(argumentsForOperator(['https://issuer.invalid', id, '0', 'enable', body.reason])).toEqual({ issuer: 'https://issuer.invalid', userId: id, version: '0', enabled: true, reason: body.reason });
  for (const args of [['https://issuer.invalid', id, '0', 'grant-admin', body.reason], ['https://issuer.invalid', id, '1.2', 'enable', body.reason], ['https://issuer.invalid', 'subject-not-uuid', '0', 'enable', body.reason], ['https://issuer.invalid', id, '0', 'enable', 'short']]) expect(() => argumentsForOperator(args)).toThrow();
});
