'use strict';
const { randomUUID } = require('crypto');
const { PrivilegedActivation, authority, duration, reason, uuid } = require('../PrivilegedActivation');
const actor = { iss: 'https://issuer.test', sub: 'subject', actor_type: 'user', identity_authorization: { userId: randomUUID(), revision: '1', linkRevision: '2', rolesRevision: 'a'.repeat(64) } };
let database; let service;
beforeEach(() => { database = { transaction: jest.fn(async () => { throw new Error('offline'); }) }; service = new PrivilegedActivation(database, { revalidate: jest.fn(async () => {}) }); });
test('an issuer subject without a canonical human context cannot use PIM self-service', () => {
  for (const user of [{ ...actor, actor_type: 'application' }, { ...actor, identity_authorization: undefined }, { ...actor, sub: '' }]) expect(() => authority(user)).toThrow();
  expect(authority(actor).userId).toBe(actor.identity_authorization.userId);
});
test.each([0, 59, 28801, '3600', null, 1.5])('duration %j is not a bounded activation', value => expect(() => duration(value)).toThrow());
test('validation accepts international reasons but not control characters, guessed users or empty explanations', () => {
  expect(reason('  Geprüfte Lizenzverwaltung  ')).toBe('Geprüfte Lizenzverwaltung'); expect(uuid(actor.identity_authorization.userId.toUpperCase())).toBe(actor.identity_authorization.userId);
  for (const value of ['short', 'new\nline', 'a'.repeat(501), null]) expect(() => reason(value)).toThrow();
  expect(() => uuid('guessed-login')).toThrow();
});
test('self-eligibility is denied before persistent storage is contacted', async () => {
  await expect(service.grantEligibility({ userId: actor.identity_authorization.userId.toUpperCase() }, actor)).rejects.toMatchObject({ status: 403 }); expect(database.transaction).not.toHaveBeenCalled();
});
test.each([{ userId: randomUUID() }, { role: 'admin' }, { approved: true }, { actor: 'admin' }])('request bodies cannot supply beneficiary or reviewer authority: %j', async patch => {
  await expect(service.request({ id: randomUUID(), eligibilityId: randomUUID(), durationSeconds: 3600, reason: 'Reviewed activation request', ...patch }, actor)).rejects.toMatchObject({ status: 400 }); expect(database.transaction).not.toHaveBeenCalled();
});
test('a source outage cannot fall back to a successful memory request or eligibility', async () => {
  await expect(service.self(actor)).rejects.toThrow('offline');
  await expect(service.request({ id: randomUUID(), eligibilityId: randomUUID(), durationSeconds: 3600, reason: 'Reviewed activation request' }, actor)).rejects.toThrow('offline');
});
