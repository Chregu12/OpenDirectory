'use strict';

const { randomUUID, createHash } = require('crypto');
const { SessionStore } = require('../SessionStore');

function fixture(principalType = 'user') {
  const session = { id: randomUUID(), issuer: 'https://sessions.test', subject: 'subject', principalType, clientId: 'application', authTime: Math.floor(Date.now() / 1000), expiresAt: Date.now() + 60000 };
  const authorization = { sid: session.id, iss: session.issuer, sub: session.subject, actor_type: principalType, aud: session.clientId, auth_time: session.authTime };
  return { session, authorization, bearer: { ...authorization, client_id: session.clientId }, refresh: { hash: createHash('sha256').update(randomUUID()).digest('hex'), scope: 'openid', authorization, expiresAt: session.expiresAt } };
}

test('production cannot switch persistent session governance into memory mode', () => {
  expect(() => new SessionStore({}, { demo: true, production: true })).toThrow();
});

test('authority errors fail closed for read, readiness and mutation', async () => {
  const offline = async () => { throw new Error('offline'); };
  const store = new SessionStore({ query: offline, pool: { connect: offline } }); const record = fixture();
  await expect(store.ready()).rejects.toMatchObject({ status: 503 });
  await expect(store.active(record.bearer)).rejects.toMatchObject({ status: 503 });
  await expect(store.create(record.session, record.refresh)).rejects.toMatchObject({ status: 503 });
});

test('explicit demo capacity or malformed binding never overwrites existing active sessions', async () => {
  const store = new SessionStore({}, { demo: true, production: false, limit: 1 }); const first = fixture(); const second = fixture();
  await store.create(first.session, first.refresh);
  await expect(store.create(second.session, second.refresh)).rejects.toMatchObject({ status: 503 });
  await expect(store.create(first.session, { ...first.refresh, authorization: { ...first.authorization, sub: 'other' } })).rejects.toMatchObject({ status: 503 });
  expect(await store.active(first.bearer)).toBe(true); expect(await store.active(second.bearer)).toBe(false);
});

test('user and application namespaces remain separate even when their subjects are identical', async () => {
  const store = new SessionStore({}, { demo: true, production: false }); const user = fixture(); const application = fixture('application');
  await store.create(user.session, user.refresh); await store.create(application.session, application.refresh);
  const owner = { issuer: user.session.issuer, subject: user.session.subject, principalType: 'application', clientId: 'application' };
  expect((await store.list(owner)).map(session => session.id)).toEqual([application.session.id]);
  await expect(store.revokeSession(user.session.id, owner)).rejects.toMatchObject({ status: 404 });
  expect(await store.active({ ...user.bearer, actor_type: 'application' })).toBe(false);
});

test('async eligibility failure rolls back refresh and cannot replace the login authorization generation', async () => {
  const store = new SessionStore({}, { demo: true, production: false }); const record = fixture();
  const context = { userId: randomUUID(), revision: '1', linkRevision: '2', rolesRevision: 'a'.repeat(64) };
  record.authorization.identity_authorization = context;
  await store.create(record.session, record.refresh);
  await expect(store.rotate(record.refresh.hash, record.session.clientId, async () => { throw Object.assign(new Error('source unavailable'), { status: 503 }); })).rejects.toMatchObject({ status: 503 });
  expect(store.memory.refresh.get(record.refresh.hash).consumedAt).toBeNull();
  await expect(store.rotate(record.refresh.hash, record.session.clientId, async () => ({ refresh: { ...record.refresh,
    hash: createHash('sha256').update('replacement').digest('hex'), authorization: { ...record.authorization, identity_authorization: { ...context, revision: '3' } } }, response: {} }))).rejects.toMatchObject({ status: 503 });
  expect(store.memory.refresh.get(record.refresh.hash).consumedAt).toBeNull();
});
