'use strict';

const { randomUUID } = require('node:crypto');
jest.mock('../RoleState', () => ({ readRoleState: jest.fn() }));
const { readRoleState } = require('../RoleState');
const { beginAuthorityCheckpoint } = require('../AuthorityCheckpoint');
let user; let initial; let client; let source; let changeRecord; let changeReceipt;
beforeEach(() => {
  const authTime = Math.floor(Date.now() / 1000); const userId = randomUUID();
  user = { iss: 'https://checkpoint.test', sub: 'operator', actor_type: 'user', jti: randomUUID(), exp: authTime + 900, auth_time: authTime,
    identity_authorization: { userId, revision: '9007199254740993', linkRevision: '9007199254740995', rolesRevision: 'a'.repeat(64) },
    amr: ['pwd', 'otp'], mfa_authorization: { schemaVersion: 1, userId, revision: '1', authTime, methods: ['pwd', 'otp'] } };
  initial = { schemaVersion: 1, tenant: { id: randomUUID(), version: '9007199254740997', generation: '9007199254740999' }, userId, linkRevision: user.identity_authorization.linkRevision, tenantGeneration: '9007199254741001' };
  source = { roles: ['role-administrator'], rolesRevision: user.identity_authorization.rolesRevision, authentication: { required: false, maxAgeSeconds: 86400 } };
  readRoleState.mockImplementation(async () => structuredClone(source)); changeRecord = value => value; changeReceipt = value => value; let lastId;
  client = { query: jest.fn(async (sql, values) => {
    if (sql.includes('identity_authority_command_context')) return { rows: [{ context: structuredClone(initial) }] };
    if (sql.startsWith('SELECT identity_authority_command_checkpoint')) { lastId = values[0]; return { rows: [{ checkpoint: changeRecord({ id: lastId, tenantId: initial.tenant.id, validUntil: values[3], recorded: true }) }] }; }
    if (sql.includes('JOIN identity_authority_command_checkpoint_events')) return { rows: changeReceipt([{ id: lastId }]) };
    return { rows: [] };
  }) };
});
afterEach(() => jest.useRealTimers());

test('the real checkpoint adapter binds exact original claims, owned incarnation, UTC and independent receiving rows', async () => {
  const seal = await beginAuthorityCheckpoint(client, user); await seal();
  expect(client.query.mock.calls[0]).toEqual(["SET LOCAL timezone='UTC'"]); expect(readRoleState).toHaveBeenCalledWith(client, user.identity_authorization.userId);
  const [sql, values] = client.query.mock.calls.find(([sql]) => sql.startsWith('SELECT identity_authority_command_checkpoint'));
  expect(sql).toContain('$4::bigint'); expect(JSON.parse(values[1])).toEqual({ ...user.identity_authorization, issuer: user.iss, subject: user.sub, tokenId: user.jti, expiresAt: user.exp });
  expect(JSON.parse(values[2])).toEqual(initial); expect(values[3]).toBe(String(user.exp)); expect(client.query.mock.calls.at(-1)[0]).toContain('checkpoint.transaction_id=txid_current()');
});
test.each([value => { delete value.jti; }, value => { value.exp = 1.5; }, value => { value.exp = Number.MAX_SAFE_INTEGER + 1; }, value => { value.identity_authorization = undefined; }, value => { value.actor_type = 'application'; }, value => { value.sub = ' '; }])('incomplete original token claims fail before checkpoint storage (%#)', async change => {
  change(user); await expect(beginAuthorityCheckpoint(client, user)).rejects.toMatchObject({ status: 401 }); expect(client.query).not.toHaveBeenCalled();
});
test('a stale original role fingerprint is not rebased to whatever the SQL source currently returns', async () => {
  source.rolesRevision = 'b'.repeat(64); await expect(beginAuthorityCheckpoint(client, user)).rejects.toMatchObject({ status: 401 }); expect(client.query.mock.calls.some(([sql]) => sql.includes('identity_authority_command_context'))).toBe(false);
});
test('missing original role assurance retains the public fresh-MFA challenge rather than rebasing the actor', async () => {
  source.authentication = { required: true, maxAgeSeconds: 300 }; delete user.mfa_authorization;
  await expect(beginAuthorityCheckpoint(client, user)).rejects.toMatchObject({ status: 428, code: 'fresh_mfa_required' }); expect(client.query.mock.calls.some(([sql]) => sql.includes('identity_authority_command_context'))).toBe(false);
});
test.each([value => { value.tenant.version = 1; }, value => { value.userId = randomUUID(); }, value => { delete value.tenantGeneration; }, value => { value.extra = true; }, value => { value.linkRevision = '1'; }])('missing or substituted SQL context is unavailable rather than an owned default (%#)', async change => {
  change(initial); await expect(beginAuthorityCheckpoint(client, user)).rejects.toMatchObject({ status: 503 });
});
test('the deadline is the earliest original token, initially required role MFA and final action MFA cutoff', async () => {
  user.auth_time -= 100; user.mfa_authorization.authTime -= 100; source.authentication = { required: true, maxAgeSeconds: 600 };
  const seal = await beginAuthorityCheckpoint(client, user); await seal({ required: true, maxAgeSeconds: 300 });
  expect(client.query.mock.calls.find(([sql]) => sql.startsWith('SELECT identity_authority_command_checkpoint'))[1][3]).toBe(String(user.auth_time + 300));
});
test('an original role-MFA cutoff cannot be extended by a later less restrictive action', async () => {
  source.authentication = { required: true, maxAgeSeconds: 300 }; const seal = await beginAuthorityCheckpoint(client, user); await seal({ required: true, maxAgeSeconds: 900 });
  expect(client.query.mock.calls.find(([sql]) => sql.startsWith('SELECT identity_authority_command_checkpoint'))[1][3]).toBe(String(user.auth_time + 300));
});
test('a disabled final MFA requirement cannot invent an auth_time requirement or extend the original token lifetime', async () => {
  delete user.auth_time; delete user.mfa_authorization; const seal = await beginAuthorityCheckpoint(client, user); await seal({ required: false, maxAgeSeconds: 300 });
  expect(client.query.mock.calls.find(([sql]) => sql.startsWith('SELECT identity_authority_command_checkpoint'))[1][3]).toBe(String(user.exp));
});
test('a later mutable caller object cannot replace the retained token, context or deadline in checkpoint evidence', async () => {
  const before = structuredClone(user); const seal = await beginAuthorityCheckpoint(client, user); user.exp += 86400; user.jti = randomUUID(); user.identity_authorization.revision = '1'; await seal();
  const values = client.query.mock.calls.find(([sql]) => sql.startsWith('SELECT identity_authority_command_checkpoint'))[1]; const originalProof = JSON.parse(values[1]);
  expect(originalProof.tokenId).toBe(before.jti); expect(originalProof.revision).toBe(before.identity_authorization.revision); expect(values[3]).toBe(String(before.exp));
});
test.each([value => ({ ...value, validUntil: String(user.exp + 1) }), value => ({ ...value, tenantId: randomUUID() }), value => ({ ...value, id: randomUUID() }), value => ({ ...value, recorded: false }), value => ({ ...value, extra: 'not a receipt' })])('a plausible but mismatched sealing result does not confirm effects (%#)', async change => {
  changeRecord = change; const seal = await beginAuthorityCheckpoint(client, user); await expect(seal()).rejects.toMatchObject({ status: 503 });
});
test.each([() => [], () => [{ id: randomUUID() }], value => [...value, ...value]])('real same-transaction root/event/pending-outbox evidence is mandatory (%#)', async change => {
  changeReceipt = change; const seal = await beginAuthorityCheckpoint(client, user); await expect(seal()).rejects.toMatchObject({ status: 503, code: 'command_checkpoint_receipt_unavailable' });
});
test('expiry before SQL sealing cannot be converted into a later arbitrary deadline', async () => {
  jest.useFakeTimers(); const now = Date.now(); jest.setSystemTime(now); user.exp = Math.floor(now / 1000) + 2; const seal = await beginAuthorityCheckpoint(client, user); jest.setSystemTime(now + 3000);
  await expect(seal()).rejects.toMatchObject({ status: 401 }); expect(client.query.mock.calls.some(([sql]) => sql.startsWith('SELECT identity_authority_command_checkpoint'))).toBe(false);
});
