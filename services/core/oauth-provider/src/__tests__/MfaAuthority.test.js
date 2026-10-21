'use strict';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { MfaAuthority, MfaCipher, base32, totp, matchedCounter } = require('../MfaAuthority');
const { boundMfa, provenMfa, validMfaContext } = require('../../../../../packages/mfa-authorization-contract');
const { generate } = require('../../scripts/mfa-key');
const http = require('http');
const { authenticateUser } = require('../authenticateUser');
const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
const actor = () => ({ sid: crypto.randomUUID(), actor_type: 'user', identity_authorization: { userId: crypto.randomUUID() } });
let service; let payload; let time;
beforeEach(() => { service = new MfaAuthority(null, { demo: true, production: false, keyFile: '' }); payload = actor(); time = jest.spyOn(Date, 'now').mockReturnValue(1700000010000); });
afterEach(() => jest.restoreAllMocks());
function claims(context) { return { ...payload, auth_time: context.authTime, amr: context.methods, mfa_authorization: context }; }
async function enabled() {
  const setup = await service.enroll(payload); const counter = Math.floor(Date.now() / 30000);
  await service.confirm(payload, totp(setup.secret, counter - 1)); return { setup, counter };
}

test.each([[59, '287082'], [1111111109, '081804'], [1111111111, '050471'], [1234567890, '005924'], [2000000000, '279037'], [20000000000, '353130']])('RFC 6238 SHA-1 vector at %s, truncated to six digits', (seconds, expected) => {
  expect(totp(secret, Math.floor(seconds / 30))).toBe(expected);
});
test('20 random bytes encode to the complete standard base32 secret', () => expect(base32(Buffer.from('12345678901234567890'))).toBe(secret));
test('only strict six-digit fresh counters inside the bounded clock window pass', () => {
  const counter = Math.floor(Date.now() / 30000); const code = totp(secret, counter);
  expect(matchedCounter(secret, code, Date.now(), counter - 1)).toBe(counter);
  for (const input of [code + ' ', ' ' + code, 123456, null, '', 'ABC123', totp(secret, counter + 2)]) expect(matchedCounter(secret, input, Date.now(), -1)).toBeNull();
  expect(matchedCounter(secret, code, Date.now(), counter)).toBeNull();
});
test('encryption authenticates canonical user, pending/active purpose and key identity', () => {
  const cipher = service.cipher; const userId = payload.identity_authorization.userId;
  const encrypted = cipher.encrypt(userId, 'pending', secret);
  const tampered = encrypted.split('.'); tampered[4] = (tampered[4][0] === 'A' ? 'B' : 'A') + tampered[4].slice(1);
  expect(encrypted).not.toContain(secret); expect(cipher.decrypt(userId, 'pending', encrypted)).toBe(secret);
  for (const [user, slot, record] of [[crypto.randomUUID(), 'pending', encrypted], [userId, 'active', encrypted], [userId, 'pending', tampered.join('.')]]) expect(() => cipher.decrypt(user, slot, record)).toThrow();
  expect(() => new MfaCipher({ demo: true, production: false, keyFile: '' }).decrypt(userId, 'pending', encrypted)).toThrow();
});
test('pending setup is session bound, expires and never counts as MFA', async () => {
  const setup = await service.enroll(payload); const weaker = await service.login(payload.identity_authorization.userId);
  expect(provenMfa(claims(weaker))).toBe(false);
  await expect(service.confirm({ ...payload, sid: crypto.randomUUID() }, totp(setup.secret, Math.floor(Date.now() / 30000)))).rejects.toMatchObject({ code: 'mfa_setup_not_pending' });
  time.mockReturnValue(Date.now() + 600001);
  await expect(service.confirm(payload, '123456')).rejects.toMatchObject({ code: 'mfa_setup_not_pending' });
});
test('enabling fences weaker tokens, requires a fresh second factor and rejects the setup-code replay', async () => {
  const weaker = claims(await service.login(payload.identity_authorization.userId)); const { setup, counter } = await enabled();
  expect(await service.matches(weaker)).toBe(false);
  await expect(service.login(payload.identity_authorization.userId)).rejects.toMatchObject({ code: 'otp_required' });
  await expect(service.login(payload.identity_authorization.userId, totp(setup.secret, counter - 1))).rejects.toMatchObject({ code: 'invalid_otp' });
  const proof = claims(await service.login(payload.identity_authorization.userId, totp(setup.secret, counter)));
  expect(provenMfa(proof)).toBe(true); expect(await service.matches(proof)).toBe(true);
  await expect(service.enroll(payload)).rejects.toMatchObject({ code: 'mfa_already_enabled' });
});
test('concurrent verifiers accept the same code exactly once', async () => {
  const { setup, counter } = await enabled();
  const results = await Promise.allSettled([service.login(payload.identity_authorization.userId, totp(setup.secret, counter)), service.login(payload.identity_authorization.userId, totp(setup.secret, counter))]);
  expect(results.filter(result => result.status === 'fulfilled')).toHaveLength(1);
  expect(service.audit.filter(event => event.action === 'verified')).toHaveLength(1);
});
test('five failures persist a five-minute lock even for an otherwise valid OTP', async () => {
  const { setup, counter } = await enabled(); const valid = totp(setup.secret, counter); let wrong = '000000';
  while ([counter - 1, counter, counter + 1].some(candidate => totp(setup.secret, candidate) === wrong)) wrong = String(Number(wrong) + 1).padStart(6, '0');
  for (let attempt = 0; attempt < 5; attempt++) await expect(service.login(payload.identity_authorization.userId, wrong)).rejects.toMatchObject({ code: 'invalid_otp' });
  await expect(service.login(payload.identity_authorization.userId, valid)).rejects.toMatchObject({ code: 'mfa_temporarily_locked' });
  time.mockReturnValue(Date.now() + 300001);
  await expect(service.login(payload.identity_authorization.userId, totp(setup.secret, Math.floor(Date.now() / 30000)))).resolves.toMatchObject({ methods: ['pwd', 'otp'] });
});
test('disabling requires an unused factor, bumps rather than deletes its incarnation, and never revives an old token', async () => {
  const weaker = claims(await service.login(payload.identity_authorization.userId)); const { setup, counter } = await enabled();
  const stronger = claims(await service.login(payload.identity_authorization.userId, totp(setup.secret, counter)));
  await expect(service.disable(payload, totp(setup.secret, counter))).rejects.toMatchObject({ code: 'invalid_otp' });
  await service.disable(payload, totp(setup.secret, counter + 1));
  expect(await service.matches(stronger)).toBe(false); expect(await service.matches(weaker)).toBe(false);
  expect((await service.login(payload.identity_authorization.userId)).revision).toBe('2');
});
test('claimed MFA, unbound user/method/time or an application actor are never evidence', async () => {
  const context = await service.login(payload.identity_authorization.userId); const original = claims(context);
  expect(boundMfa(original)).toBe(true); expect(validMfaContext(context)).toBe(true);
  for (const changed of [{ ...original, amr: ['pwd', 'otp'] }, { ...original, auth_time: original.auth_time + 1 }, { ...original, actor_type: 'application' }, { ...original, identity_authorization: { userId: crypto.randomUUID() } }, { ...original, mfa_authorization: { ...context, extra: true } }]) {
    expect(boundMfa(changed)).toBe(false); expect(await service.matches(changed)).toBe(false);
  }
});
test('an unavailable persistent authority fails closed, never switches to demo memory', async () => {
  const persistent = Object.assign(Object.create(MfaAuthority.prototype), { database: { pool: { connect: async () => { throw new Error('offline'); } } }, demo: false });
  await expect(persistent.login(payload.identity_authorization.userId)).rejects.toMatchObject({ status: 503 });
});
test('protected persistent key generation is exclusive, restart-stable and rejects public permissions or invalid material', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'od-mfa-key-')); const filename = path.join(directory, 'mfa.key');
  try {
    const kid = generate(filename); const cipher = new MfaCipher({ keyFile: filename, production: true }); expect(cipher.kid).toBe(kid);
    expect(fs.statSync(filename).mode & 0o777).toBe(0o600); expect(() => generate(filename)).toThrow();
    const encrypted = cipher.encrypt(payload.identity_authorization.userId, 'active', secret);
    expect(new MfaCipher({ keyFile: filename, production: true }).decrypt(payload.identity_authorization.userId, 'active', encrypted)).toBe(secret);
    fs.chmodSync(filename, 0o644); expect(() => new MfaCipher({ keyFile: filename })).toThrow();
    fs.chmodSync(filename, 0o600); fs.writeFileSync(filename, 'broken'); expect(() => new MfaCipher({ keyFile: filename, demo: true })).toThrow();
    expect(() => new MfaCipher({ keyFile: '', production: true })).toThrow(); expect(() => new MfaCipher({ demo: true, production: true })).toThrow();
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});
test('password reauthentication never forwards credentials through an upstream redirect', async () => {
  const previous = process.env.AUTH_SERVICE_URL; let forwarded = 0;
  const destination = http.createServer((_request, response) => { forwarded++; response.end('{}'); });
  const upstream = http.createServer((_request, response) => { response.writeHead(307, { Location: `http://127.0.0.1:${destination.address().port}/collect` }); response.end(); });
  try {
    await new Promise(resolve => destination.listen(0, '127.0.0.1', resolve)); await new Promise(resolve => upstream.listen(0, '127.0.0.1', resolve));
    process.env.AUTH_SERVICE_URL = `http://127.0.0.1:${upstream.address().port}`;
    await expect(authenticateUser({ username: 'owner', password: 'never-forward-this' })).resolves.toEqual({ status: 503, error: 'authentication_unavailable' });
    expect(forwarded).toBe(0);
  } finally {
    if (previous === undefined) delete process.env.AUTH_SERVICE_URL; else process.env.AUTH_SERVICE_URL = previous;
    for (const server of [upstream, destination]) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
  }
});

test('federated primary authentication is labelled honestly and does not count as local MFA', async () => {
  const context = await service.login(payload.identity_authorization.userId, undefined, 'federated');
  expect(context.methods).toEqual(['federated']);
  expect(boundMfa(claims(context))).toBe(true);
  expect(provenMfa(claims(context))).toBe(false);
  expect(await service.matches(claims(context))).toBe(true);
  await expect(service.login(payload.identity_authorization.userId, undefined, 'otp')).rejects.toMatchObject({ code: 'invalid_authentication_method' });
});
test('federated login still requires an independently verified local OTP', async () => {
  const { setup, counter } = await enabled();
  await expect(service.login(payload.identity_authorization.userId, undefined, 'federated')).rejects.toMatchObject({ code: 'otp_required' });
  const context = await service.login(payload.identity_authorization.userId, totp(setup.secret, counter), 'federated');
  expect(context.methods).toEqual(['federated', 'otp']);
  expect(provenMfa(claims(context))).toBe(true);
  expect(await service.matches(claims(context))).toBe(true);
});
