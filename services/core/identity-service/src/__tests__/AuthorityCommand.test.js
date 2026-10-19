'use strict';

const { randomUUID } = require('node:crypto');
jest.mock('../AuthorityCheckpoint', () => ({ ...jest.requireActual('../AuthorityCheckpoint'), beginAuthorityCheckpoint: jest.fn(async () => async () => {}) }));
const { AuthorityCommand } = require('../AuthorityCommand');
const { beginAuthorityCheckpoint } = require('../AuthorityCheckpoint');

function actor() {
  const userId = randomUUID(); const authTime = Math.floor(Date.now() / 1000);
  return { iss: 'https://command.test', sub: randomUUID(), jti: randomUUID(), exp: authTime + 300, actor_type: 'user', roles: ['user'],
    identity_authorization: { userId, revision: '1', linkRevision: '1', rolesRevision: 'a'.repeat(64) },
    auth_time: authTime, amr: ['pwd', 'otp'], mfa_authorization: { schemaVersion: 1, userId, revision: '1', authTime, methods: ['pwd', 'otp'] } };
}
function storage(events = []) {
  const client = { query: jest.fn(async () => { events.push('write'); return { rows: [] }; }) };
  return { client, transaction: jest.fn(async (operation, options) => {
    events.push(['begin', options]);
    try { const result = await operation(client); events.push('commit'); return result; }
    catch (error) { events.push('rollback'); throw error; }
  }) };
}
afterEach(() => { jest.restoreAllMocks(); jest.useRealTimers(); });

test('the original bearer is checked before storage and after actual effects but before commit or result delivery', async () => {
  const events = []; const database = storage(events); const user = actor(); const revalidate = jest.fn(async () => { events.push('issuer'); }); const commands = new AuthorityCommand(database, { revalidate });
  const value = await commands.run(user, 'Bearer exact-original', async client => { await client.query('write'); return { id: 'confirmed-effect' }; }, { actor: user.sub });
  expect(value).toEqual({ id: 'confirmed-effect' }); expect(events).toEqual(['issuer', ['begin', { actor: user.sub }], 'write', 'issuer', 'commit']);
  expect(revalidate).toHaveBeenCalledTimes(2); expect(revalidate.mock.calls.every(([expected, authorization]) => expected.jti === user.jti && authorization === 'Bearer exact-original')).toBe(true);
});
test('withdrawn initial authority never starts a transaction or waits on a target row', async () => {
  const database = storage(); const revalidate = jest.fn(async () => { throw Object.assign(new Error('withdrawn'), { status: 401 }); });
  await expect(new AuthorityCommand(database, { revalidate }).run(actor(), 'Bearer withdrawn', jest.fn())).rejects.toMatchObject({ status: 401 }); expect(database.transaction).not.toHaveBeenCalled();
});
test.each([401, 503])('final issuer failure %s rolls back actual work and cannot return an earlier successful projection', async status => {
  const events = []; const database = storage(events); let checks = 0; const revalidate = jest.fn(async () => { if (++checks === 2) throw Object.assign(new Error('original-authority-unavailable'), { status }); });
  await expect(new AuthorityCommand(database, { revalidate }).run(actor(), 'Bearer original', async client => { await client.query('write'); return { success: true }; })).rejects.toMatchObject({ status });
  expect(events).toContain('write'); expect(events).toContain('rollback'); expect(events).not.toContain('commit');
});
test('idempotent and early no-op results still require the original final issuer checkpoint', async () => {
  const database = storage(); const revalidate = jest.fn(async () => {});
  expect(await new AuthorityCommand(database, { revalidate }).run(actor(), 'Bearer original', async () => ({ unchanged: true }))).toEqual({ unchanged: true }); expect(revalidate).toHaveBeenCalledTimes(2);
});
test('a command cannot replace original claims with its admitted post-change role fingerprint or another token', async () => {
  const user = actor(); const before = structuredClone(user); const revalidate = jest.fn(async () => {});
  await new AuthorityCommand(storage(), { revalidate }).run(user, 'Bearer original', async () => {
    user.jti = randomUUID(); user.roles = ['admin']; user.identity_authorization.rolesRevision = 'b'.repeat(64); return { authorization: 'Bearer internal-replacement' };
  });
  expect(revalidate.mock.calls.map(([expected]) => expected)).toEqual([before, before]); expect(revalidate.mock.calls.map(([, authorization]) => authorization)).toEqual(['Bearer original', 'Bearer original']);
});
test('a database failure is preserved rather than retried, committed or converted into a positive response', async () => {
  const events = []; const revalidate = jest.fn(async () => {}); const operation = jest.fn(async () => { throw new Error('actual SQL failure'); });
  await expect(new AuthorityCommand(storage(events), { revalidate }).run(actor(), 'Bearer original', operation)).rejects.toThrow('actual SQL failure');
  expect(operation).toHaveBeenCalledTimes(1); expect(revalidate).toHaveBeenCalledTimes(1); expect(events).toContain('rollback');
});
test('the production default rejects a missing original bearer even for plausible canonical administrator claims', async () => {
  const database = storage(); const user = { ...actor(), roles: ['admin'] };
  await expect(new AuthorityCommand(database).run(user, undefined, jest.fn())).rejects.toMatchObject({ status: 401 }); expect(database.transaction).not.toHaveBeenCalled();
});
test('the production default sends the exact original token uncached and rejects a substituted issuer token identity', async () => {
  const user = actor(); const database = storage(); let checks = 0;
  const fetchMock = jest.spyOn(global, 'fetch').mockImplementation(async () => new Response(JSON.stringify({ schemaVersion: 1, active: true, issuer: user.iss, subject: user.sub,
    tokenId: ++checks === 1 ? user.jti : randomUUID(), expiresAt: user.exp }), { status: 200, headers: { 'Content-Type': 'application/json' } }));
  await expect(new AuthorityCommand(database).run(user, 'Bearer exact-original', async () => ({ confirmed: true }))).rejects.toMatchObject({ status: 503 });
  expect(fetchMock).toHaveBeenCalledTimes(2); for (const [, options] of fetchMock.mock.calls) expect(options).toMatchObject({ method: 'GET', cache: 'no-store', redirect: 'error', headers: { Authorization: 'Bearer exact-original' } });
});
test('fixed fresh MFA can expire while awaiting the final real issuer response and still rolls back', async () => {
  jest.useFakeTimers(); const start = new Date('2026-10-19T12:00:00Z'); jest.setSystemTime(start); const user = actor(); user.auth_time -= 299; user.mfa_authorization.authTime -= 299;
  const events = []; let checks = 0; const revalidate = jest.fn(async () => { if (++checks === 2) jest.setSystemTime(new Date(start.getTime() + 2000)); });
  await expect(new AuthorityCommand(storage(events), { revalidate }).run(user, 'Bearer original', async () => ({ saved: true }), {}, { required: true, maxAgeSeconds: 300 })).rejects.toMatchObject({ status: 428 }); expect(events).toContain('rollback');
});
test('parallel authority commands retain independent immutable original actors and tokens', async () => {
  const first = actor(); const second = actor(); const checks = []; const revalidate = async (user, token) => { checks.push([user.jti, token]); await Promise.resolve(); };
  const commands = new AuthorityCommand(storage(), { revalidate }); await Promise.all([commands.run(first, 'Bearer first', async () => 'first'), commands.run(second, 'Bearer second', async () => 'second')]);
  expect(checks.filter(([jti, token]) => jti === first.jti && token === 'Bearer first')).toHaveLength(2); expect(checks.filter(([jti, token]) => jti === second.jti && token === 'Bearer second')).toHaveLength(2);
});
test('a protected action can derive its final MFA requirement from the actual resulting role without skipping either issuer check', async () => {
  const user = actor(); delete user.mfa_authorization; const events = []; const revalidate = jest.fn(async () => {});
  await expect(new AuthorityCommand(storage(events), { revalidate }).run(user, 'Bearer original', async client => { await client.query('actual protected effect'); return { role: 'admin' }; }, {}, result => result.role === 'admin' ? { required: true, maxAgeSeconds: 300 } : undefined)).rejects.toMatchObject({ status: 428 });
  expect(revalidate).toHaveBeenCalledTimes(2); expect(events).toContain('write'); expect(events).toContain('rollback'); expect(events).not.toContain('commit');
});
test('a failed mandatory SQL checkpoint after successful issuer validation still rolls back without delivering its result', async () => {
  const events = []; const revalidate = jest.fn(async () => {}); beginAuthorityCheckpoint.mockImplementationOnce(async () => async () => { throw Object.assign(new Error('missing checkpoint evidence'), { status: 503 }); });
  await expect(new AuthorityCommand(storage(events), { revalidate }).run(actor(), 'Bearer original', async client => { await client.query('write'); return { confirmed: true }; })).rejects.toMatchObject({ status: 503 });
  expect(revalidate).toHaveBeenCalledTimes(2); expect(events).toContain('rollback'); expect(events).not.toContain('commit');
});
test('deferred physical original-authentication expiry is a denial, not a committed success', async () => {
  const database = { transaction: jest.fn(async () => { throw Object.assign(new Error('Original command assurance expired at commit'), { code: '28000' }); }) };
  await expect(new AuthorityCommand(database, { revalidate: async () => {} }).run(actor(), 'Bearer original', jest.fn())).rejects.toMatchObject({ status: 401, code: '28000' });
});
