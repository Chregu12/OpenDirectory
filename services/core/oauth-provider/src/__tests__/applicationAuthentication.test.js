'use strict';

const { randomUUID } = require('crypto');
const { ClientRegistry, etag } = require('../ClientRegistry');
const { acceptsAuthentication, freshMfa } = require('../applicationAuthentication');
const { parseEnrollment, MfaEnrollment } = require('../MfaEnrollment');
const userId = randomUUID(); const now = Math.floor(Date.now() / 1000);
const actor = (role = 'application-authentication-administrator', time = now) => ({ iss: 'https://policy.test', sub: 'operator', actor_type: 'user', client_id: 'control', roles: [role], auth_time: time, amr: ['pwd', 'otp'],
  identity_authorization: { userId, revision: '1', linkRevision: '1', rolesRevision: 'a'.repeat(64) },
  mfa_authorization: { schemaVersion: 1, userId, revision: '1', methods: ['pwd', 'otp'], authTime: time } });
const change = { required: true, maxAgeSeconds: 300, reason: 'Reviewed application MFA requirement' };
let registry; let client;
beforeEach(async () => { registry = new ClientRegistry({}, { demo: true, production: false }); client = await registry.create({ name: 'Owned application', redirectUris: ['https://policy.test/callback'] }, actor('admin')); });
test('policy staff reads only a known client policy, not profile, secret or registration inventories', async () => {
  const result = await registry.authentication(client.clientId, actor()); expect(Object.keys(result).sort()).toEqual(['canManage','clientId','maxAgeSeconds','name','protected','required','requiresFreshMfa','version']);
  expect(result).toMatchObject({ required: false, canManage: true }); await expect(registry.list(actor())).rejects.toMatchObject({ status: 403 });
  expect(client.mfaRequired).toBeUndefined(); expect(client.mfaMaxAgeSeconds).toBeUndefined();
  await expect(registry.mutate(client.clientId, etag(client), { enabled: true }, actor())).rejects.toMatchObject({ status: 403 });
});
test('metadata editors and authentication readers cannot change policies', async () => {
  for (const role of ['application-administrator', 'application-authentication-reader']) await expect(registry.setAuthentication(client.clientId, etag(client), change, actor(role))).rejects.toMatchObject({ status: 403 });
});
test('a fresh actual proof, exact version and separate control client are all required for policy writes', async () => {
  for (const unproven of [{ ...actor(), amr: ['pwd'] }, { ...actor(), mfa_authorization: undefined }, actor('application-authentication-administrator', now - 301)]) {
    await expect(registry.setAuthentication(client.clientId, etag(client), change, unproven)).rejects.toMatchObject({ code: 'fresh_mfa_required' });
    expect(await registry.authentication(client.clientId, unproven)).toMatchObject({ canManage: false, requiresFreshMfa: true });
  }
  await expect(registry.setAuthentication(client.clientId, null, change, actor())).rejects.toMatchObject({ status: 428 });
  await expect(registry.setAuthentication(client.clientId, '"old"', change, actor())).rejects.toMatchObject({ status: 412 });
  await expect(registry.setAuthentication(client.clientId, etag(client), change, { ...actor(), client_id: client.clientId })).rejects.toMatchObject({ status: 409 });
  const saved = await registry.setAuthentication(client.clientId, etag(client), change, actor()); expect(saved).toMatchObject({ version: '2', required: true, maxAgeSeconds: 300 });
  expect(registry.memory.audit.at(-1)).toMatchObject({ action: 'authentication_changed', reason: change.reason });
  expect(registry.memory.audit.at(-1).authentication).toEqual({ required: true, maxAgeSeconds: 300 });
});
test('protected scopes require a fresh global administrator and cannot be weakened through metadata fields', async () => {
  const protectedApp = await registry.create({ name: 'Privileged', redirectUris: ['https://policy.test/callback'], scopes: ['roles'] }, actor('admin'));
  expect(await registry.authentication(protectedApp.clientId, actor())).toMatchObject({ protected: true, canManage: false, requiresFreshMfa: false });
  await expect(registry.setAuthentication(protectedApp.clientId, etag(protectedApp), change, actor())).rejects.toMatchObject({ status: 403 });
  await expect(registry.setAuthentication(protectedApp.clientId, etag(protectedApp), change, actor('admin'))).resolves.toMatchObject({ required: true });
  await expect(registry.mutate(client.clientId, etag(client), { mfaRequired: false }, actor('admin'))).rejects.toMatchObject({ status: 400 });
});
test.each([{ ...change, maxAgeSeconds: 299 }, { ...change, maxAgeSeconds: 86401 }, { ...change, maxAgeSeconds: '300' }, { ...change, required: 'true' }, { ...change, reason: 'short' }, { ...change, reason: 'not\nallowed' }, { ...change, userId }, { required: true, maxAgeSeconds: 300 }])('malformed policy %j cannot be interpreted as a weaker rule', async value => {
  await expect(registry.setAuthentication(client.clientId, etag(client), value, actor())).rejects.toMatchObject({ status: 400 });
});
test('MFA age remains bound to the original login and cannot be reset by a claimed amr, refresh time or mismatched owner', () => {
  const policy = { mfaRequired: true, mfaMaxAgeSeconds: 300 };
  expect(acceptsAuthentication(policy, actor(), now + 300)).toBe(true); expect(acceptsAuthentication(policy, actor(), now + 301)).toBe(false);
  expect(freshMfa({ ...actor(), auth_time: now + 5 }, 300, now)).toBe(false);
  for (const payload of [{ ...actor(), amr: ['pwd'] }, { ...actor(), auth_time: now + 1 }, { ...actor(), identity_authorization: { ...actor().identity_authorization, userId: randomUUID() } }, { ...actor(), mfa_authorization: undefined }]) expect(acceptsAuthentication(policy, payload, now)).toBe(false);
  expect(acceptsAuthentication(policy, { actor_type: 'application' }, now)).toBe(true); expect(acceptsAuthentication({ mfaRequired: false }, { actor_type: 'unknown' })).toBe(false);
});
test('policy generations prevent a weaker context from reviving after enforcement is relaxed', async () => {
  const enabled = await registry.mutate(client.clientId, etag(client), { enabled: true }, actor('admin'));
  const original = { ...actor(), client_id: client.clientId, client_revision: enabled.version, amr: ['pwd'], mfa_authorization: undefined };
  expect(await registry.active(original)).toBe(true); const enforced = await registry.setAuthentication(client.clientId, etag(enabled), change, actor()); expect(await registry.active(original)).toBe(false);
  await registry.setAuthentication(client.clientId, etag(enforced), { ...change, required: false }, actor()); expect(await registry.active(original)).toBe(false);
});
test('registration challenges are opaque, purpose-hashed and unavailable in a demo authority', async () => {
  const challenge = randomUUID() + '.' + 'A'.repeat(43); expect(parseEnrollment(challenge).tokenHash).toMatch(/^[a-f0-9]{64}$/);
  expect(() => parseEnrollment(challenge.slice(0, -1) + 'B')).toThrow();
  await expect(new MfaEnrollment({ mfa: { demo: true } }).start('client', 'owner')).rejects.toMatchObject({ status: 503 });
});
