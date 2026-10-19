'use strict';

const { TokenRevocationStore } = require('../TokenRevocationStore');
const hash = require('crypto').createHash('sha256').update('credential').digest('hex');

test('production cannot enable an in-memory revocation authority', () => {
  expect(() => new TokenRevocationStore({}, { demo: true, production: true })).toThrow();
});

test('storage errors never become active credentials or acknowledged revocations', async () => {
  const store = new TokenRevocationStore({ query: async () => { throw new Error('offline'); } });
  await expect(store.ready()).rejects.toMatchObject({ status: 503 });
  await expect(store.revoked(hash)).rejects.toMatchObject({ status: 503 });
  await expect(store.revoke(hash, 'client', Date.now() + 10000)).rejects.toMatchObject({ status: 503 });
});

test('explicit nonproduction demo mode expires entries individually and never clears existing revocations at capacity', async () => {
  let now = 100;
  const store = new TokenRevocationStore({}, { demo: true, production: false, now: () => now, limit: 1 });
  await store.revoke(hash, 'client', 200);
  await store.revoke(hash, 'client', 180);
  const other = require('crypto').createHash('sha256').update('other').digest('hex');
  await expect(store.revoke(other, 'client', 300)).rejects.toMatchObject({ status: 503 });
  expect(await store.revoked(hash)).toBe(true);
  now = 201;
  expect(await store.revoked(hash)).toBe(false);
  await store.revoke(other, 'client', 300);
  expect(await store.revoked(other)).toBe(true);
});

test('only stores token hashes and actual credential expiry, not raw bearer secrets or arbitrary TTLs', async () => {
  const query = jest.fn(async () => ({ rows: [] }));
  const store = new TokenRevocationStore({ query });
  const expiry = Date.now() + 8000000;
  await store.revoke(hash, 'client', expiry);
  expect(query).toHaveBeenCalledWith(expect.stringContaining('GREATEST'), [hash, 'client', new Date(expiry)]);
  await expect(store.revoke('raw-token', 'client', expiry)).rejects.toMatchObject({ status: 503 });
  expect(query).toHaveBeenCalledTimes(1);
});
