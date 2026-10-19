'use strict';

const { randomUUID, randomBytes } = require('crypto');
const { MfaRecovery, recoveryHash, parseChallenge } = require('../MfaRecovery');
const code = '11223344-55667788-99aabbcc-ddeeff00';
test('backup hashes bind a 128-bit code to one canonical user and disclose no recoverable code', () => {
  const owner = randomUUID(); const digest = recoveryHash(owner, code);
  expect(digest).toMatch(/^[a-f0-9]{64}$/); expect(digest).not.toContain(code); expect(recoveryHash(randomUUID(), code)).not.toBe(digest);
});
test.each(['', '112233445566778899aabbccddeeff00', code.toUpperCase(), code + ' ', 123456, null])('invalid backup formatting %j is not guessed or coerced', value => expect(() => recoveryHash(randomUUID(), value)).toThrow());
test('an opaque canonical 256-bit challenge has a separate hashed purpose and is not an access credential', () => {
  const id = randomUUID(); const value = id + '.' + randomBytes(32).toString('base64url'); const parsed = parseChallenge(value);
  expect(parsed.id).toBe(id); expect(parsed.tokenHash).toMatch(/^[a-f0-9]{64}$/); expect(parsed.tokenHash).not.toContain(value);
});
test.each(['', 'eyJhbGciOiJSUzI1NiJ9.e30.signature', randomUUID() + '.' + 'A'.repeat(42), randomUUID() + '.' + 'A'.repeat(42) + 'B', randomUUID() + '.' + 'A'.repeat(43) + '.extra', 123456, null])('untrusted or noncanonical challenge %j is rejected before a lookup', value => expect(() => parseChallenge(value)).toThrow());
test('recovery never falls back to the demo MFA map', async () => {
  const recovery = new MfaRecovery({ mfa: { demo: true }, identity: {}, issuer: 'https://test' });
  await expect(recovery.ready()).rejects.toMatchObject({ status: 503 }); await expect(recovery.start('subject', {}, code)).rejects.toMatchObject({ status: 503 }); await expect(recovery.confirm('bad', '123456')).rejects.toMatchObject({ status: 503 });
});
